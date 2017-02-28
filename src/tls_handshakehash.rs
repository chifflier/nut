use openssl::error::ErrorStack;
use openssl::hash::{MessageDigest,Hasher};

pub struct HandshakeHash {
    hasher: Option<Hasher>,
    buffer: Vec<u8>,
}

impl HandshakeHash {
    pub fn new() -> HandshakeHash {
        HandshakeHash{
            hasher: None,
            buffer: Vec::new(),
        }
    }

    pub fn set_hash(&mut self, d: MessageDigest) -> Result<(),ErrorStack> {
        self.hasher = Some(try!(Hasher::new(d)));
        try!(self.extend(&b""[..]));
        Ok(())
    }

    pub fn extend(&mut self, v: &[u8]) -> Result<(),ErrorStack> {
        match self.hasher {
            None    => self.buffer.extend_from_slice(v),
            Some(ref mut h) => {
                if self.buffer.len() > 0 {
                    try!(h.update(&self.buffer));
                    self.buffer.truncate(0);
                };
                try!(h.update(v));
            },
        };
        Ok(())
    }

    pub fn finish(&mut self) -> Result<Vec<u8>,ErrorStack> {
        match self.hasher {
            None    => panic!("no hasher, no finish"),
            Some(ref mut h) => {
                h.finish()
            },
        }
    }
}
