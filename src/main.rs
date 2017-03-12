// #![feature(trace_macros)]

// trace_macros!(true);

#[macro_use]
extern crate log;
extern crate env_logger;


extern crate byteorder;
extern crate rand;
extern crate openssl;

extern crate hexdump;
use hexdump::hexdump_iter;

#[macro_use]
extern crate nom;
extern crate tls_parser;

#[macro_use]
extern crate rusticata_macros;

use tls_parser::*;
use tls_parser::serialize::*;

use nom::IResult;
use rusticata_macros::GenError;

use std::io::prelude::*;
use std::net::TcpStream;

use byteorder::{BigEndian, WriteBytesExt};

use rand::Rng;
use rand::os::OsRng;

use openssl::error::ErrorStack;
use openssl::x509::X509;
use openssl::rsa::PKCS1_PADDING;
use openssl::hash::MessageDigest;
use openssl::pkey::PKey;
use openssl::sign::Signer;
use openssl::symm::{Cipher,Crypter,Mode};

mod tls_handshakehash;
use tls_handshakehash::*;

struct KeyBlock {
    client_mac_key: Vec<u8>,
    server_mac_key: Vec<u8>,
    client_enc_key: Vec<u8>,
    server_enc_key: Vec<u8>,
    client_write_iv: Vec<u8>,
    server_write_iv: Vec<u8>,
}

struct TlsContext {
    client_random: Vec<u8>,
    server_random: Vec<u8>,
    ciphersuite: &'static TlsCipherSuite,
    compression: u8,
    server_cert: Vec<u8>,
    master_secret: Vec<u8>,

    key_block: KeyBlock,

    hh: HandshakeHash,
}

impl TlsContext {
    pub fn new() -> TlsContext {
        TlsContext{
            client_random: Vec::with_capacity(32),
            server_random: Vec::with_capacity(32),
            ciphersuite: TlsCipherSuite::from_id(0).unwrap(),
            compression: 0,
            server_cert: Vec::new(),
            master_secret: Vec::new(),
            key_block: KeyBlock{
                client_mac_key: Vec::new(),
                server_mac_key: Vec::new(),
                client_enc_key: Vec::new(),
                server_enc_key: Vec::new(),
                client_write_iv: Vec::new(),
                server_write_iv: Vec::new(),
            },
            hh: HandshakeHash::new(),
        }
    }
}

#[derive(Debug)]
pub enum MyError {
    OpenSSLError(ErrorStack),
    IoError(std::io::Error),
    GenError(GenError),

    UnsupportedCipher,
    UnsupportedCompression,
    UnsupportedMac,
}

impl std::convert::From<openssl::error::ErrorStack> for MyError {
    fn from(e: ErrorStack) -> MyError {
        MyError::OpenSSLError(e)
    }
}

impl std::convert::From<std::io::Error> for MyError {
    fn from(e: std::io::Error) -> MyError {
        MyError::IoError(e)
    }
}

impl std::convert::From<GenError> for MyError {
    fn from(e: GenError) -> MyError {
        MyError::GenError(e)
    }
}

#[inline]
fn debug_hexdump(label: &str, data: &[u8]) {
    debug!("{}",label);
    for line in hexdump_iter(data) {
        debug!("{}",line);
    }
}

fn get_cipher_obj(c: &TlsCipherSuite) -> Result<Cipher,MyError> {
    match (&c.enc,&c.enc_mode,c.enc_size) {
        (&TlsCipherEnc::Aes,&TlsCipherEncMode::Cbc,128) => Ok(Cipher::aes_128_cbc()),
        (&TlsCipherEnc::Aes,&TlsCipherEncMode::Cbc,256) => Ok(Cipher::aes_256_cbc()),
        _ => Err(MyError::UnsupportedCipher),
    }
}

fn get_mac_obj(c: &TlsCipherSuite) -> Result<MessageDigest,MyError> {
    match &c.mac {
        &TlsCipherMac::HmacSha1   => Ok(MessageDigest::sha1()),
        &TlsCipherMac::HmacSha256 => Ok(MessageDigest::sha256()),
        _ => Err(MyError::UnsupportedMac),
    }
}

#[inline]
fn hmac_sign(key: &PKey, hashalg: &MessageDigest, a: &[u8]) -> Result<Vec<u8>,ErrorStack> {
    let mut signer = try!(Signer::new(*hashalg, key));
    try!(signer.update(a));
    signer.finish()
}

#[inline]
fn concat_sign(key: &PKey, hashalg: &MessageDigest, a: &[u8], b: &[u8]) -> Result<Vec<u8>,ErrorStack> {
    let mut signer = try!(Signer::new(*hashalg, key));
    try!(signer.update(a));
    try!(signer.update(b));
    signer.finish()
}

#[inline]
fn concat(a: &[u8], b: &[u8]) -> Vec<u8> {
    let mut ret = Vec::new();
    ret.extend_from_slice(a);
    ret.extend_from_slice(b);
    ret
}

fn p_hash(out: &mut [u8], hashalg: &MessageDigest, secret: &[u8], seed: &[u8]) -> Result<(),MyError> {
    // let hmac_key = hmac::SigningKey::new(hashalg, secret);
    let hmac_key = try!(PKey::hmac(secret));
    // let mut signer = Signer::new(*hashalg, &hmac_key);

    // A(1)
    let mut current_a = try!(hmac_sign(&hmac_key, hashalg, seed));

    let mut offs = 0;

    while offs < out.len() {
        // P_hash[i] = HMAC_hash(secret, A(i) + seed)
        let p_term = try!(concat_sign(&hmac_key, hashalg, current_a.as_ref(), seed));
        offs += try!(out[offs..].as_mut().write(p_term.as_ref()));

        // A(i+1) = HMAC_hash(secret, A(i))
        //current_a = hmac::sign(&hmac_key, current_a.as_ref());
        current_a = try!(hmac_sign(&hmac_key, hashalg, current_a.as_ref()));
    };

    Ok(())
}

fn prf(out: &mut [u8],
       hashalg: &MessageDigest,
       secret: &[u8],
       label: &[u8],
       seed: &[u8]) -> Result<(),MyError> {
    let joined_seed = concat(label, seed);
    p_hash(out, hashalg, secret, &joined_seed)
}

fn compute_master_secret(ctx: &mut TlsContext, pms: &[u8]) -> Result<(),MyError> {
    let mut buffer : [u8; 256] = [0; 256];

    debug_hexdump("client random:", &ctx.client_random);
    debug_hexdump("server random:", &ctx.server_random);

    let label = b"master secret";
    let seed = concat(&ctx.client_random,&ctx.server_random);
    // let hashalg = try!(get_mac_obj(ctx.ciphersuite));
    // XXX SHA-256 is used when TLS >= 1.2 is negociated
    let hashalg = MessageDigest::sha256();

    try!(prf(&mut buffer, &hashalg, pms, label, &seed));
    let master_secret = &buffer[..48];

    debug_hexdump(&format!("Master secret ({}):",master_secret.len()), &master_secret);

    ctx.master_secret.extend_from_slice(&master_secret);
    Ok(())
}

fn compute_keys(ctx: &mut TlsContext) -> Result<(),MyError> {
    let cipher = ctx.ciphersuite;
    let ossl_cipher = try!(get_cipher_obj(cipher));

    let mac_key_length = (cipher.mac_size / 8) as usize;
    let enc_key_length = (cipher.enc_size / 8) as usize;
    let fixed_iv_length = ossl_cipher.block_size(); // XXX IV length can be different !
    let sz = 2*mac_key_length + 2*enc_key_length + 2*fixed_iv_length;
    let mut buffer : [u8; 256] = [0; 256];

    let label = b"key expansion";
    let seed = concat(&ctx.server_random,&ctx.client_random); // note order: server + client
    // let hashalg = try!(get_mac_obj(ctx.ciphersuite));
    // XXX SHA-256 is used when TLS >= 1.2 is negociated
    let hashalg = MessageDigest::sha256();

    try!(prf(&mut buffer, &hashalg, &ctx.master_secret, label, &seed));

    let _key_block = &buffer[..sz];
    debug_hexdump("key block", &_key_block);

    let mut ofs = 0;
    ctx.key_block.client_mac_key.extend_from_slice( &_key_block[ofs .. ofs + mac_key_length] );
    ofs += mac_key_length;
    ctx.key_block.server_mac_key.extend_from_slice( &_key_block[ofs .. ofs + mac_key_length] );
    ofs += mac_key_length;
    ctx.key_block.client_enc_key.extend_from_slice( &_key_block[ofs .. ofs + enc_key_length] );
    ofs += enc_key_length;
    ctx.key_block.server_enc_key.extend_from_slice( &_key_block[ofs .. ofs + enc_key_length] );
    ofs += enc_key_length;
    // XXX read IV if ciphersuite is using IV
    ctx.key_block.client_write_iv.extend_from_slice( &_key_block[ofs .. ofs + fixed_iv_length] );
    ofs += fixed_iv_length;
    ctx.key_block.server_write_iv.extend_from_slice( &_key_block[ofs .. ofs + fixed_iv_length] );
    // ofs += fixed_iv_length;
    Ok(())
}

fn protect_data(cipher: &Cipher, mac: MessageDigest, plaintext: &[u8], iv: &[u8], key_aes: &[u8], key_mac: &[u8], seq_num: u64, content_type: u8)
        -> Result<Vec<u8>,MyError> {
    let hmac_key = try!(PKey::hmac(key_mac));
    let mut signer = try!(Signer::new(mac, &hmac_key));

    let mut buffer : [u8; 256] = [0; 256];
    let res = do_gen!(
        (&mut buffer,0),
        gen_be_u32!(0) >> gen_be_u32!(seq_num as u32) >> // XXX gen_be_u64!(seq_num)
        gen_be_u8!(content_type) >>
        gen_be_u16!(0x0303) >>
        gen_be_u16!(plaintext.len()) >>
        gen_slice!(plaintext)
    );
    let (b,idx) = try!(res);

    debug_hexdump("plaintext to MAC", &b[..idx]);

    try!(signer.update(&b[..idx]));
    let hmac_computed = try!(signer.finish());

    debug_hexdump("Message MAC", &hmac_computed);

    // append: plaintext + hmac_computed + padding
    let mut v = Vec::new();
    v.extend_from_slice(plaintext);
    v.extend_from_slice(&hmac_computed);
    // add padding manually (see later)
    let pad_to = cipher.block_size();
    let mut padding_length = pad_to - (v.len() % pad_to);
    if padding_length == 0 { padding_length = pad_to; };
    for _i in 0 .. padding_length {
        v.push((padding_length-1) as u8);
    };

    debug_hexdump("plaintext + hmac + padding:", &v);

    // aes_128_cbc adds padding by default, but using the wrong type
    let mut crypter = try!(Crypter::new(*cipher,Mode::Encrypt,key_aes,Some(iv)));
    crypter.pad(false);

    let mut out = vec![0; v.len() + cipher.block_size()];

    let count = try!(crypter.update(&v, &mut out));
    let sz = try!(crypter.finalize(&mut out[count..]));
    out.truncate(count+sz);

    Ok(out)
}

fn encrypt_hash(ctx: &mut TlsContext, hash: &[u8]) -> Result<Vec<u8>,MyError> {
    let mut buffer : [u8; 256] = [0; 256];

    let label = b"client finished";
    let seed = hash;
    let hashalg = try!(get_mac_obj(ctx.ciphersuite));
    // XXX SHA-256 is used when TLS >= 1.2 is negociated
    // let hashalg = MessageDigest::sha256();
    let prf_alg = MessageDigest::sha256();

    try!(prf(&mut buffer, &prf_alg, &ctx.master_secret, label, &seed));

    let mut buffer_out : [u8; 256] = [0; 256];
    let res = do_gen!(
        (&mut buffer_out,0),
        gen_be_u8!(TlsHandshakeType::Finished as u8) >>
        gen_be_u24!(12) >>
        gen_copy!(buffer,12)
    );
    let (b,idx) = try!(res);
    let content = &b[..idx];

    debug_hexdump("Finished message:", content);

    // now protect record
    let key_mac = &ctx.key_block.client_mac_key;
    let key_aes = &ctx.key_block.client_enc_key;
    let session_iv = &ctx.key_block.client_write_iv;

    debug_hexdump("key_mac:", key_mac);
    debug_hexdump("key_aes:", key_aes);

    let cipher = try!(get_cipher_obj(ctx.ciphersuite));

    // 0x16: message type (handshake)
    let p = try!(protect_data(&cipher, hashalg, content, session_iv, key_aes, key_mac, 0, 0x16));

    // protected
    let mut reply = Vec::new();
    // reply.extend_from_slice(iv);
    reply.extend_from_slice(session_iv);
    reply.extend_from_slice(&p);

    debug_hexdump("IV + protected:", &reply);

    Ok(reply)
}

fn prepare_key(stream: &mut TcpStream, ctx: &mut TlsContext) -> Result<(),MyError> {
    let mut rng = try!(OsRng::new());
    let mut rand : [u8; 48] = [0; 48];

    // concat protocol version (2 bytes) + 46 of random
    rand[0] = 0x03;
    rand[1] = 0x03;
    rng.fill_bytes(&mut rand[2..]);

    // compute master secret
    try!(compute_master_secret(ctx, &rand));

    // derive keys
    try!(compute_keys(ctx));

    // hexdump(&rand);

    // then encrypt to server public key
    let x509 = try!(X509::from_der(&ctx.server_cert));
    let pkey = try!(x509.public_key());
    let rsa = try!(pkey.rsa());
    let mut encrypted : [u8; 512] = [0; 512];
    let sz = try!(rsa.public_encrypt(&rand,&mut encrypted, PKCS1_PADDING));
    debug_hexdump(&format!("sz: {}",sz), &encrypted[..sz]);

    // put it into the CKE
    let cke = TlsMessageHandshake::ClientKeyExchange(
        TlsClientKeyExchangeContents{
            parameters: &encrypted[..sz],
        }
    );

    // send records
    let record_cke = TlsPlaintext{
        hdr: TlsRecordHeader {
            record_type: TlsRecordType::Handshake as u8,
            version: 0x0303,
            len: 0,
        },
        msg: vec![TlsMessage::Handshake(cke)],
    };
    let record_ccs = TlsPlaintext{
        hdr: TlsRecordHeader {
            record_type: TlsRecordType::ChangeCipherSpec as u8,
            version: 0x0303,
            len: 0,
        },
        msg: vec![TlsMessage::ChangeCipherSpec],
    };

    let mut mem : [u8; 1024] = [0; 1024];

    let res = do_gen!(
        (&mut mem,0),
        gen_tls_plaintext(&record_cke) >>
        gen_tls_plaintext(&record_ccs)
    );

    match res {
        Ok((b,idx)) => {
            debug!("Sending CKE + CCS, size {}",idx);
            // XXX 5.. because we hash only the *message*
            // XXX substract 6, to remove the CCS from the hash
            debug!("Extending hash len={}",&b[5..idx-6].len());
            try!(ctx.hh.extend(&b[5..idx-6]));
            let res_hash = try!(ctx.hh.finish());
            debug_hexdump("res_hash: ", &res_hash);

            let e_h = try!(encrypt_hash(ctx, &res_hash));
            debug_hexdump("e_h: ", &e_h);

            let r = do_gen!(
                (b,idx),
                gen_slice!(&[0x16, 0x03, 0x03]) >>
                gen_be_u16!(e_h.len()) >>
                gen_slice!(&e_h)
            );
            let (b,idx) = try!(r);

            let _ = stream.write(&b[..idx]);
        },
        Err(e)    => println!("Error: {:?}",e),
    };

    Ok(())
}


fn handle_message(ctx: &mut TlsContext, msg: &TlsMessage, stream: &mut TcpStream)
        -> Result<(),MyError> {
    match msg {
        &TlsMessage::Handshake(ref msg) => {
            debug!("msg: {:?}",msg);
            match msg {
                &TlsMessageHandshake::ServerHello(ref content) => {
                    ctx.compression = content.compression;
                    let cipher = TlsCipherSuite::from_id(content.cipher);
                    debug!("cipher: {:?}",cipher);
                    if cipher.is_none() {return Err(MyError::UnsupportedCipher);};
                    if ctx.compression > 0 {return Err(MyError::UnsupportedCompression);};
                    ctx.ciphersuite = cipher.unwrap();
                    // let hmac = try!(get_mac_obj(ctx.ciphersuite));
                    // XXX SHA-256 is used when TLS >= 1.2 is negociated
                    let hmac = MessageDigest::sha256();
                    ctx.hh.set_hash(hmac).unwrap();
                    try!(ctx.server_random.write_u32::<BigEndian>(content.rand_time));
                    ctx.server_random.extend_from_slice(content.rand_data);
                },
                &TlsMessageHandshake::Certificate(ref content) => {
                    ctx.server_cert.extend_from_slice(content.cert_chain[0].data);
                },
                &TlsMessageHandshake::ServerDone(ref _content) => {
                    // XXX prepare ClienKeyExchange + ChangeCipherSpec + Finished
                    try!(prepare_key(stream, ctx));
                },
                _ => {
                    warn!("Unsupported message: {:?}",msg);
                },
            }
        },
        _ => debug!("msg: {:?}",msg),
    };
    Ok(())
}

fn handle_record(ctx: &mut TlsContext, r: &TlsRawRecord, stream: &mut TcpStream) -> Result<(),MyError> {
    debug!("record: {:?}", r);
    match r.hdr.record_type {
        0x16 => {
            // XXX exclude HelloRequest messages
            debug!("Extending hash len={}",r.data.len());
            try!(ctx.hh.extend(r.data));
        },
        _ => (),
    };

    let res = parse_tls_record_with_header(r.data,r.hdr.clone());
    match res {
        IResult::Done(rem2,ref msg_list) => {
            for msg in msg_list {
                try!(handle_message(ctx, msg, stream));
            };
            if rem2.len() > 0 {
                warn!("extra bytes in TLS record: {:?}",rem2);
            };
        }
        IResult::Incomplete(_) => {
            warn!("Defragmentation required (TLS record)");
        },
        IResult::Error(e) => { warn!("parse_tls_record_with_header failed: {:?}",e); },
    };
    Ok(())
}




fn main() {
    let _ = env_logger::init().unwrap();
    openssl::init();

    let mut rng = OsRng::new().unwrap();
    let rand_time = rng.next_u32();
    let mut rand_data : [u8; 28] = [0; 28];
    rng.fill_bytes(&mut rand_data);

    let mut ctx = TlsContext::new();

    let ciphers = vec![
        0x003d, // TLS_RSA_WITH_AES_256_CBC_SHA256
        0x003c, // TLS_RSA_WITH_AES_128_CBC_SHA256
        0x0035, // TLS_RSA_WITH_AES_256_CBC_SHA
        0x002f, // TLS_RSA_WITH_AES_128_CBC_SHA
    ];
    let comp = vec![0x00];

    let ch = TlsMessageHandshake::ClientHello(
        TlsClientHelloContents {
            version: 0x0303,
            rand_time: rand_time,
            rand_data: &rand_data,
            session_id: None,
            ciphers: ciphers,
            comp: comp,
            ext: None,
        });

    let rec_ch = TlsPlaintext {
        hdr: TlsRecordHeader {
            record_type: TlsRecordType::Handshake as u8,
            version: 0x0301,
            len: 0,
        },
        msg: vec![TlsMessage::Handshake(ch)],
    };

    ctx.client_random.write_u32::<BigEndian>(rand_time).unwrap();
    ctx.client_random.extend_from_slice(&rand_data);

    let mut stream = TcpStream::connect("127.0.0.1:8443").unwrap();

    {
        let mut mem : [u8; 218] = [0; 218];
        let s = &mut mem[..];

        let res = gen_tls_plaintext((s,0), &rec_ch);
        match res {
            Ok((b,idx)) => {
                debug!("Sending client hello ({})",idx);
                // XXX 5.. because we hash only the *message*
                debug!("Extending hash len={}",&b[5..idx].len());
                ctx.hh.extend(&b[5..idx]).unwrap();
                let _ = stream.write(&b[..idx]);
            },
            Err(e)    => println!("Error: {:?}",e),
        };
    }

    {
        let mut mem : [u8; 4096] = [0; 4096];
        debug!("Reading server response");
        let r = stream.read(&mut mem);
        let sz = r.unwrap();
        let s = &mem[..sz];

        let mut cur_i = s;
        while cur_i.len() > 0 {
            match parse_tls_raw_record(cur_i) {
                IResult::Done(rem, ref r) => {
                    // debug!("rem: {:?}",rem);
                    cur_i = rem;
                    handle_record(&mut ctx, r, &mut stream).unwrap();
                    // status |= self.parse_record_level(r);
                },
                IResult::Incomplete(_) => {
                    debug!("Fragmentation required (TCP level)");
                    // self.tcp_buffer.extend_from_slice(cur_i);
                    break;
                },
                IResult::Error(e) => { warn!("Parsing failed: {:?}",e); break },
            }
        };
    }
}

#[cfg(test)]
mod tests {
    use super::*;
#[test]
fn test_prf_224() {
    // taken from https://www.ietf.org/mail-archive/web/tls/current/msg03416.html
    let mut buffer : [u8; 256] = [0; 256];

    let secret = &[
        0xe1, 0x88, 0x28, 0x74, 0x03, 0x52, 0xb5, 0x30,
        0xd6, 0x9b, 0x34, 0xc6, 0x59, 0x7d, 0xea, 0x2e,
    ];
    let seed = &[
        0xf5, 0xa3, 0xfe, 0x6d, 0x34, 0xe2, 0xe2, 0x85,
        0x60, 0xfd, 0xca, 0xf6, 0x82, 0x3f, 0x90, 0x91,
    ];
    let label = b"test label";
    let hashalg = MessageDigest::sha224();

    prf(&mut buffer, &hashalg, secret, label, seed).unwrap();

    let expected = &[
        0x22, 0x4d, 0x8a, 0xf3, 0xc0, 0x45, 0x33, 0x93,
        0xa9, 0x77, 0x97, 0x89, 0xd2, 0x1c, 0xf7, 0xda,
        0x5e, 0xe6, 0x2a, 0xe6, 0xb6, 0x17, 0x87, 0x3d,
        0x48, 0x94, 0x28, 0xef, 0xc8, 0xdd, 0x58, 0xd1,
        0x56, 0x6e, 0x70, 0x29, 0xe2, 0xca, 0x3a, 0x5e,
        0xcd, 0x35, 0x5d, 0xc6, 0x4d, 0x4d, 0x92, 0x7e,
        0x2f, 0xbd, 0x78, 0xc4, 0x23, 0x3e, 0x86, 0x04,
        0xb1, 0x47, 0x49, 0xa7, 0x7a, 0x92, 0xa7, 0x0f,
        0xdd, 0xf6, 0x14, 0xbc, 0x0d, 0xf6, 0x23, 0xd7,
        0x98, 0x60, 0x4e, 0x4c, 0xa5, 0x51, 0x27, 0x94,
        0xd8, 0x02, 0xa2, 0x58, 0xe8, 0x2f, 0x86, 0xcf,
    ];
    assert_eq!(&expected[..],&buffer[..expected.len()]);
}

#[test]
fn test_prf_256() {
    // taken from https://www.ietf.org/mail-archive/web/tls/current/msg03416.html
    let mut buffer : [u8; 256] = [0; 256];

    let secret = &[
        0x9b, 0xbe, 0x43, 0x6b, 0xa9, 0x40, 0xf0, 0x17,
        0xb1, 0x76, 0x52, 0x84, 0x9a, 0x71, 0xdb, 0x35,
    ];
    let seed = &[
        0xa0, 0xba, 0x9f, 0x93, 0x6c, 0xda, 0x31, 0x18,
        0x27, 0xa6, 0xf7, 0x96, 0xff, 0xd5, 0x19, 0x8c,
    ];
    let label = b"test label";
    let hashalg = MessageDigest::sha256();

    prf(&mut buffer, &hashalg, secret, label, seed).unwrap();

    let expected = &[
        0xe3, 0xf2, 0x29, 0xba, 0x72, 0x7b, 0xe1, 0x7b,
        0x8d, 0x12, 0x26, 0x20, 0x55, 0x7c, 0xd4, 0x53,
        0xc2, 0xaa, 0xb2, 0x1d, 0x07, 0xc3, 0xd4, 0x95,
        0x32, 0x9b, 0x52, 0xd4, 0xe6, 0x1e, 0xdb, 0x5a,
        0x6b, 0x30, 0x17, 0x91, 0xe9, 0x0d, 0x35, 0xc9,
        0xc9, 0xa4, 0x6b, 0x4e, 0x14, 0xba, 0xf9, 0xaf,
        0x0f, 0xa0, 0x22, 0xf7, 0x07, 0x7d, 0xef, 0x17,
        0xab, 0xfd, 0x37, 0x97, 0xc0, 0x56, 0x4b, 0xab,
        0x4f, 0xbc, 0x91, 0x66, 0x6e, 0x9d, 0xef, 0x9b,
        0x97, 0xfc, 0xe3, 0x4f, 0x79, 0x67, 0x89, 0xba,
        0xa4, 0x80, 0x82, 0xd1, 0x22, 0xee, 0x42, 0xc5,
        0xa7, 0x2e, 0x5a, 0x51, 0x10, 0xff, 0xf7, 0x01,
        0x87, 0x34, 0x7b, 0x66,
    ];
    assert_eq!(&expected[..],&buffer[..expected.len()]);
}

#[test]
fn test_prf_384() {
    // taken from https://www.ietf.org/mail-archive/web/tls/current/msg03416.html
    let mut buffer : [u8; 256] = [0; 256];

    let secret = &[
        0xb8, 0x0b, 0x73, 0x3d, 0x6c, 0xee, 0xfc, 0xdc,
        0x71, 0x56, 0x6e, 0xa4, 0x8e, 0x55, 0x67, 0xdf,
    ];
    let seed = &[
        0xcd, 0x66, 0x5c, 0xf6, 0xa8, 0x44, 0x7d, 0xd6,
        0xff, 0x8b, 0x27, 0x55, 0x5e, 0xdb, 0x74, 0x65,
    ];
    let label = b"test label";
    let hashalg = MessageDigest::sha384();

    prf(&mut buffer, &hashalg, secret, label, seed).unwrap();

    let expected = &[
        0x7b, 0x0c, 0x18, 0xe9, 0xce, 0xd4, 0x10, 0xed,
        0x18, 0x04, 0xf2, 0xcf, 0xa3, 0x4a, 0x33, 0x6a,
        0x1c, 0x14, 0xdf, 0xfb, 0x49, 0x00, 0xbb, 0x5f,
        0xd7, 0x94, 0x21, 0x07, 0xe8, 0x1c, 0x83, 0xcd,
        0xe9, 0xca, 0x0f, 0xaa, 0x60, 0xbe, 0x9f, 0xe3,
        0x4f, 0x82, 0xb1, 0x23, 0x3c, 0x91, 0x46, 0xa0,
        0xe5, 0x34, 0xcb, 0x40, 0x0f, 0xed, 0x27, 0x00,
        0x88, 0x4f, 0x9d, 0xc2, 0x36, 0xf8, 0x0e, 0xdd,
        0x8b, 0xfa, 0x96, 0x11, 0x44, 0xc9, 0xe8, 0xd7,
        0x92, 0xec, 0xa7, 0x22, 0xa7, 0xb3, 0x2f, 0xc3,
        0xd4, 0x16, 0xd4, 0x73, 0xeb, 0xc2, 0xc5, 0xfd,
        0x4a, 0xbf, 0xda, 0xd0, 0x5d, 0x91, 0x84, 0x25,
        0x9b, 0x5b, 0xf8, 0xcd, 0x4d, 0x90, 0xfa, 0x0d,
        0x31, 0xe2, 0xde, 0xc4, 0x79, 0xe4, 0xf1, 0xa2,
        0x60, 0x66, 0xf2, 0xee, 0xa9, 0xa6, 0x92, 0x36,
        0xa3, 0xe5, 0x26, 0x55, 0xc9, 0xe9, 0xae, 0xe6,
        0x91, 0xc8, 0xf3, 0xa2, 0x68, 0x54, 0x30, 0x8d,
        0x5e, 0xaa, 0x3b, 0xe8, 0x5e, 0x09, 0x90, 0x70,
        0x3d, 0x73, 0xe5, 0x6f,
    ];
    assert_eq!(&expected[..],&buffer[..expected.len()]);
}

#[test]
fn test_prf_512() {
    // taken from https://www.ietf.org/mail-archive/web/tls/current/msg03416.html
    let mut buffer : [u8; 256] = [0; 256];

    let secret = &[
        0xb0, 0x32, 0x35, 0x23, 0xc1, 0x85, 0x35, 0x99,
        0x58, 0x4d, 0x88, 0x56, 0x8b, 0xbb, 0x05, 0xeb,
    ];
    let seed = &[
        0xd4, 0x64, 0x0e, 0x12, 0xe4, 0xbc, 0xdb, 0xfb,
        0x43, 0x7f, 0x03, 0xe6, 0xae, 0x41, 0x8e, 0xe5,
    ];
    let label = b"test label";
    let hashalg = MessageDigest::sha512();

    prf(&mut buffer, &hashalg, secret, label, seed).unwrap();

    let expected = &[
        0x12, 0x61, 0xf5, 0x88, 0xc7, 0x98, 0xc5, 0xc2,
        0x01, 0xff, 0x03, 0x6e, 0x7a, 0x9c, 0xb5, 0xed,
        0xcd, 0x7f, 0xe3, 0xf9, 0x4c, 0x66, 0x9a, 0x12,
        0x2a, 0x46, 0x38, 0xd7, 0xd5, 0x08, 0xb2, 0x83,
        0x04, 0x2d, 0xf6, 0x78, 0x98, 0x75, 0xc7, 0x14,
        0x7e, 0x90, 0x6d, 0x86, 0x8b, 0xc7, 0x5c, 0x45,
        0xe2, 0x0e, 0xb4, 0x0c, 0x1c, 0xf4, 0xa1, 0x71,
        0x3b, 0x27, 0x37, 0x1f, 0x68, 0x43, 0x25, 0x92,
        0xf7, 0xdc, 0x8e, 0xa8, 0xef, 0x22, 0x3e, 0x12,
        0xea, 0x85, 0x07, 0x84, 0x13, 0x11, 0xbf, 0x68,
        0x65, 0x3d, 0x0c, 0xfc, 0x40, 0x56, 0xd8, 0x11,
        0xf0, 0x25, 0xc4, 0x5d, 0xdf, 0xa6, 0xe6, 0xfe,
        0xc7, 0x02, 0xf0, 0x54, 0xb4, 0x09, 0xd6, 0xf2,
        0x8d, 0xd0, 0xa3, 0x23, 0x3e, 0x49, 0x8d, 0xa4,
        0x1a, 0x3e, 0x75, 0xc5, 0x63, 0x0e, 0xed, 0xbe,
        0x22, 0xfe, 0x25, 0x4e, 0x33, 0xa1, 0xb0, 0xe9,
        0xf6, 0xb9, 0x82, 0x66, 0x75, 0xbe, 0xc7, 0xd0,
        0x1a, 0x84, 0x56, 0x58, 0xdc, 0x9c, 0x39, 0x75,
        0x45, 0x40, 0x1d, 0x40, 0xb9, 0xf4, 0x6c, 0x7a,
        0x40, 0x0e, 0xe1, 0xb8, 0xf8, 0x1c, 0xa0, 0xa6,
        0x0d, 0x1a, 0x39, 0x7a, 0x10, 0x28, 0xbf, 0xf5,
        0xd2, 0xef, 0x50, 0x66, 0x12, 0x68, 0x42, 0xfb,
        0x8d, 0xa4, 0x19, 0x76, 0x32, 0xbd, 0xb5, 0x4f,
        0xf6, 0x63, 0x3f, 0x86, 0xbb, 0xc8, 0x36, 0xe6,
        0x40, 0xd4, 0xd8, 0x98,
    ];
    assert_eq!(&expected[..],&buffer[..expected.len()]);
}

#[test]
fn test_aes_256_cbc() {
    let cipher = openssl::symm::Cipher::aes_256_cbc();
    println!("key size: {}", cipher.key_len());
    println!("iv len: {:?}", cipher.iv_len());
    println!("block size: {}", cipher.block_size());

    let key = vec![0; 32];
    let iv = vec![1; 16];
    let block = vec![2; 16];

    let _ = openssl::symm::encrypt(cipher, &key, Some(&iv), &block).unwrap();
}
} // cfg(test_
