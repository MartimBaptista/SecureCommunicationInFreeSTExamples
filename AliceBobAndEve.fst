import SecureChannel

--Alice sends two values to bob, bob replies with productd of those values, all through secure channel

--In this exemple Eve (eavesdropper) intercepts and attempts to read the messages sent by Alice and Bob.

type SecureMultiplication = EstablishSecureChannelA ; SecureSendInt ; SecureSendInt ; SecureReceiveInt ; SecureClose

alice : Int -> Int -> SecureMultiplication -> Int 
alice n m c =
    let sc = establishSecureAuthenticatedChannelA @(SecureSendInt ; SecureSendInt ; SecureReceiveInt ; SecureClose) "Alice/Keys/AliceKey.priv" "Alice/Keys/BobKey.pub" c in
    let sc = secureSendInt n @(SecureSendInt ; SecureReceive ; SecureClose) sc in
    let sc = secureSendInt m @(SecureReceive ; SecureClose) sc in
    let (res, sc) = secureReceiveInt @SecureClose sc in
    secureClose sc;
    res

bob : dualof SecureMultiplication -> ()
bob c =
    let sc = establishSecureAuthenticatedChannelB @(SecureReceiveInt ; SecureReceiveInt ; SecureSendInt ; SecureWait) "Bob/Keys/BobKey.priv" "Bob/Keys/AliceKey.pub" c in
    let (n, sc) = secureReceiveInt @(SecureReceiveInt ; SecureSendInt ; SecureWait) sc in
    let (m, sc) = secureReceiveInt @(SecureSendInt ; SecureWait) sc in
    let sc = secureSendInt (n*m) @SecureWait sc in
    secureWait sc

eve : dualof SecureMultiplication -> SecureMultiplication 1-> ()
eve ca cb =
    --Alice DH share
    let (msg, ca) = receive ca in
    print @String $ "Alice sent: " ^^ show @Integer msg;
    let cb = send msg cb in

    --Bob DH share
    let (msg, cb) = receive cb in
    print @String $ "Bob sent: " ^^ show @Integer msg;
    let ca = send msg ca in

    --ChaCha20 Seed share
    let (msg, ca) = receive ca in
    print @String $ "Alice sent: " ^^ show @Integer msg;
    let cb = send msg cb in

    --Fist alice value
    let (msg, ca) = receive ca in
    print @String $ "Alice sent: " ^^ show @Bits msg;
    let cb = send msg cb in

    --Second alice value
    let (msg, ca) = receive ca in
    print @String $ "Alice sent: " ^^ show @Bits msg;
    let cb = send msg cb in

    --Bobs response
    let (msg, cb) = receive cb in
    print @String $ "Bob sent: " ^^ show @Bits msg;
    let ca = send msg ca in

    wait ca;
    close cb

main : Int
main = 
    let (ca, dualca) = new @SecureMultiplication () in
    let (cb, dualcb) = new @SecureMultiplication () in
    fork @() (\_:() 1-> bob dualcb);
    fork @() (\_:() 1-> eve dualca cb);
    alice 3 7 ca