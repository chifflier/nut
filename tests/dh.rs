extern crate openssl;
use openssl::bn::*;

extern crate hexdump;

#[test]
fn test_dh() {
    /// taken from http://prestonhunt.com/journal/index.php?tag=diffie-hellman

    let a = BigNum::from_hex_str("440051d6f0b55ea967ab31c68a8b5e37d910dae0e2d459a486459caadf367516").unwrap();

    let b = BigNum::from_hex_str("5daec7867980a3248ce3578fc75f1b0f2df89d306fa452cde07a048aded92656").unwrap();

    let p = BigNum::from_hex_str("FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AAAC42DAD33170D04507A33A85521ABDF1CBA64ECFB850458DBEF0A8AEA71575D060C7DB3970F85A6E1E4C7ABF5AE8CDB0933D71E8C94E04A25619DCEE3D2261AD2EE6BF12FFA06D98A0864D87602733EC86A64521F2B18177B200CBBE117577A615D6C770988C0BAD946E208E24FA074E5AB3143DB5BFCE0FD108E4B82D120A93AD2CAFFFFFFFFFFFFFFFF").unwrap();

    let true_g_a = BigNum::from_hex_str("5a0d3d4e049faa939ffa6a375b9c3c16a4c39753d19ff7da36bc391ea72fc0f68c929bdb400552ed84e0900c7a44c3222fd54d7148256862886bfb4016bd2d03c4c4cf476567c291770e47bd59d0aa5323cfddfc5596e0d6558c480ee8b0c62599834d4581a796a01981468789164504afbd29ce9936e86a290c5f00f8ba986b48010f3e5c079c7f351ddca2ee1fd50846b37bf7463c2b0f3d001b1317ac3069cd89e2e4927ed3d40875a6049af649d2dc349db5995a7525d70a3a1c9b673f5482f83343bd90d45e9c3962dc4a4bf2b4adb37e9166b2ddb31ccf11c5b9e6c98e0a9a3377abba56b0f4283b2eaa69f5368bc107e1c22599f88dd1924d0899c5f153462c911a8293078aefee9fb2389a7854833fcea61cfecbb49f828c361a981a5fedecf13796ae36e36c15a16670af96996c3c45a30e900e18c858f6232b5f7072bdd9e47d7fc61246ef5d19765739f38509284379bc319d9409e8fe236bd29b0335a5bc5bb0424ee44de8a19f864a159fda907d6f5a30ebc0a17e3628e490e5").unwrap();

    let true_g_b = BigNum::from_hex_str("dc14c6f6d85b3d58b54abb306d5568292ed785d39ed73643666a1b4a4684654f88bbedf0414c59c70dd990b447b3c3250a4a23673ea9361a79be33760906ef127627fa9e7f9107e736759cff990c44fce2407e7ce1c7d61a83b85c8285a9bf947cc1e582642a8a863e4e0d57f2584b255229c4d353551e86ac2bbce413c7e5541cc2e68d7101d57830cde1c91bd48c03d190147201f39697f65cc2f445e851623bea585c8205d8e8ca91b54daefb6fe5ac46e942b5ea6e04495bd2f6cb1188c1b44a342e5dab2917165e0935d74369b7669868c9d4d5b14833f31e5694991e73353a33f5f4dc61ff5752517b71806da2e47efc78d22dd8dac4f115019d575d60b78761404413bff6e314329bf1e52b9238f87964a5a300c726c0950fac9464593c306ece4d92813fd7142e1618b3efbb3fea25f9e17708592507d8be73efd569761e7ff4b016edd0c5c385a8ec161a44f2d67c1c6b397d8f6c3fa797bcd95e3fb8f4ecba7ebf6620570ef4914e75eaf9752ba471faf7ccc55373069c21531194").unwrap();

    let true_shared_secret = BigNum::from_hex_str("bcecd344c6f42f35aced542b7ceb684a623bf9ad3ebf2a649afcbe7c9fd2127e1d2b08bab2473cddbf44fa3f98a56ad75ee75a66e0dc0bfbc246fb579a6d52753222ea82e4fcee51fef53d24af4c5f00fdbaf7b3c55a0e4f8b5f2e2751b5ca3f98988ca308b511bd2e35776784dc852f85199eb052aa12a3b4f5e9cabe79861011a6c34e9b116f06fcb3b59ee73975cf6529118f63b068f22422cbac11e118f1fc3a06c79787f8c0ee90f87864b9fac65f7567256abd1da21122d83e4026e9d4835e5e7710cd5ab47e887d10dd7556bf5f27679d634aa1c2f8a8cfc31859cb72d0e08efa9b01a88b213fb60463faeb6324497b77442076cf81b9955634dceeebbcc19b171857d823d190798f391e1910b7ceecccbaa5085632cf7660bb069b82721f7c3361a4512b8a25ac32f16ea3322e872f54d2db8ea7b815e125cd47b0c62a51ae425f6c69568ec43bb8810f62e8447ccb190f59ad1c212a50aa20f066c5732ca60e6728ea2bc91a82fecc806f813330a6944affc69a562f3501514cc70f").unwrap();

    let g = BigNum::from_hex_str("2").unwrap();

    let mut bn_ctx = openssl::bn::BigNumContext::new().unwrap();

    let mut g_a = BigNum::new().unwrap();
    g_a.mod_exp(&g, &a, &p, &mut bn_ctx).unwrap();
    assert_eq!(g_a, true_g_a);

    let mut g_b = BigNum::new().unwrap();
    g_b.mod_exp(&g, &b, &p, &mut bn_ctx).unwrap();
    assert_eq!(g_b, true_g_b);

    let mut tmp_1 = BigNum::new().unwrap();
    let mut shared_secret_1 = BigNum::new().unwrap();
    tmp_1.mod_exp(&g, &a, &p, &mut bn_ctx).unwrap();
    shared_secret_1.mod_exp(&tmp_1, &b, &p, &mut bn_ctx).unwrap();

    let mut tmp_2 = BigNum::new().unwrap();
    let mut shared_secret_2 = BigNum::new().unwrap();
    tmp_2.mod_exp(&g, &b, &p, &mut bn_ctx).unwrap();
    shared_secret_2.mod_exp(&tmp_2, &a, &p, &mut bn_ctx).unwrap();

    assert_eq!(shared_secret_1, shared_secret_2);
    assert_eq!(shared_secret_1, true_shared_secret);
    assert_eq!(shared_secret_2, true_shared_secret);
}
