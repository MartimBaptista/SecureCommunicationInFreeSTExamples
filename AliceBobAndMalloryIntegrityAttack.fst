import SecureChannel

--Alice sends two values to bob, bob replies with productd of those values, all through secure channel

--In this exemple mallory (eavesdropper) intercepts and attempts to read the messages sent by Alice and Bob.

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

mallory : dualof SecureMultiplication -> SecureMultiplication 1-> ()
mallory ca cb =
    --Alice DH share
    let (msg, ca) = receive ca in
    let cb = send msg cb in

    --Bob DH share
    let (msg, cb) = receive cb in
    let ca = send msg ca in

    --ChaCha20 Seed share
    let (msg, ca) = receive ca in
    let cb = send msg cb in

    --Fist alice value
    let (msg, ca) = receive ca in
    let cb = send msg cb in

    --Second alice value
    let (msg, ca) = receive ca in
    let cb = send msg cb in

    --Bobs response
    let (msg, cb) = receive cb in
    let bits = lxorI (_getBits msg) 4i in --Flip third bit, causes change of +-2
    let ca = send (Bits bits) ca in

    wait ca;
    close cb

main : Int
main = 
    let (ca, dualca) = new @SecureMultiplication () in
    let (cb, dualcb) = new @SecureMultiplication () in
    fork @() (\_:() 1-> bob dualcb);
    fork @() (\_:() 1-> mallory dualca cb);
    alice 3 7 ca
