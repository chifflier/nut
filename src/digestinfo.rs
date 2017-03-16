use nom::*;
use der_parser::*;

#[derive(Debug)]
pub struct DigestInfo {
    pub oid:    Vec<u64>,
    pub digest: Vec<u8>,
}

impl DigestInfo {
    /// Convert a DER ovject to a DigestInfo
    ///
    /// Return code in case of error:
    ///   - 0: object is not a sequence
    ///   - 1: sequence has wrong length (must be 2)
    ///   - 2: sequence item 0 has wrong type (must be an Sequence of length 2)
    ///   - 3: sequence item 0[0] has wrong type (must be an OID)
    ///   - 4: sequence item 0[1] has wrong type (must be a Null)
    ///   - 5: sequence item 1 has wrong type (must be an OctetString)
    pub fn from_derobject(obj: &DerObject) -> Result<DigestInfo,u32> {
        match obj.content {
            DerObjectContent::Sequence(ref v) => {
                let mut oid = Vec::new();
                if v.len() != 2 { return Err(1); };
                match v[0].content {
                    DerObjectContent::Sequence(ref v2) => {
                        if v2.len() != 2 { return Err(2); };
                        if v2[0].tag != DerTag::Oid as u8 { return Err(3); };
                        if v2[1].tag != DerTag::Null as u8 { return Err(4); };
                        match v2[0].content {
                            DerObjectContent::OID(ref oid_obj) => {
                                oid.extend_from_slice(&oid_obj)
                            },
                            _ => { return Err(3); }
                        };
                    },
                    _ => { return Err(2); },
                }
                let mut digest = Vec::new();
                if v[1].tag != DerTag::OctetString as u8 { return Err(5); };
                digest.extend_from_slice(v[1].content.as_slice().unwrap());
                Ok(DigestInfo {
                    oid:    oid,
                    digest: digest,
                })
            },
            _ => { return Err(0); }
        }
    }
}

pub fn parse_digest_algorithm(i: &[u8]) -> IResult<&[u8],DerObject> {
    parse_der_sequence_defined!(
        i,
        parse_der_oid,  // algorithm OID
        parse_der_null, // parameters
    )
}

pub fn parse_digest_info(i: &[u8]) -> IResult<&[u8],Result<DigestInfo,u32>> {
    let der_object =  parse_der_sequence_defined!(
        i,
        parse_digest_algorithm,
        parse_der_octetstring
    );
    match der_object {
        IResult::Done(rem,obj)   => IResult::Done(rem,DigestInfo::from_derobject(&obj)),
        IResult::Incomplete(e) => IResult::Incomplete(e),
        IResult::Error(e)      => IResult::Error(e),
    }
}
