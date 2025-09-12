import SecureChannel

--Alice sends two values to bob, bob replies with productd of those values, all through secure channel

--In this exemple Eve (eavesdropper) intercepts and attempts to read the messages sent by Alice and Bob.

type SecureMultiplication = EstablishSecureChannelA ; SecureSendInt ; SecureSendInt ; SecureReceiveInt ; SecureClose

alice : Int -> Int -> SecureMultiplication -> Int 
alice n m c =
    let sc = establishSecureAuthenticatedChannelA @(SecureSendInt ; SecureSendInt ; SecureReceiveInt ; SecureClose) "Alice/Keys/AliceKey.priv" "Alice/Keys/BobKey.pub" c in
    --let sc = establishSecureChannelA @(SecureSendInt ; SecureSendInt ; SecureReceiveInt ; SecureClose) c in
    let sc = secureSendInt n @(SecureSendInt ; SecureReceive ; SecureClose) sc in
    let sc = secureSendInt m @(SecureReceive ; SecureClose) sc in
    let (res, sc) = secureReceiveInt @SecureClose sc in
    secureClose sc;
    res

bob : dualof SecureMultiplication -> ()
bob c =
    let sc = establishSecureAuthenticatedChannelB @(SecureReceiveInt ; SecureReceiveInt ; SecureSendInt ; SecureWait) "Bob/Keys/BobKey.priv" "Bob/Keys/AliceKey.pub" c in
    --let sc = establishSecureChannelB @(SecureReceiveInt ; SecureReceiveInt ; SecureSendInt ; SecureWait) c in
    let (n, sc) = secureReceiveInt @(SecureReceiveInt ; SecureSendInt ; SecureWait) sc in
    let (m, sc) = secureReceiveInt @(SecureSendInt ; SecureWait) sc in
    let sc = secureSendInt (n*m) @SecureWait sc in
    secureWait sc

mallory : dualof SecureMultiplication -> SecureMultiplication 1-> ()
mallory ca cb =
    --Establish "Secure" channel with Alice
    let sca = establishSecureChannelB @(SecureReceiveInt ; SecureReceiveInt ; SecureSendInt ; SecureWait) ca in

    --Establish "Secure" channel with Bob
    let scb = establishSecureChannelA @(SecureSendInt ; SecureSendInt ; SecureReceiveInt ; SecureClose) cb in

    --Fist alice value
    let (msg, sca) = secureReceiveInt @(SecureReceiveInt ; SecureSendInt ; SecureWait) sca in
    print @String $ "Alice sent: " ^^ show @Int msg;
    let scb = secureSendInt msg @(SecureSendInt ; SecureReceive ; SecureClose) scb in

    --Second alice value
    let (msg, sca) = secureReceiveInt @(SecureSendInt ; SecureWait) sca in
    print @String $ "Alice sent: " ^^ show @Int msg;
    let scb = secureSendInt msg @(SecureReceive ; SecureClose) scb in

    --Bobs response
    let (msg, scb) = secureReceiveInt @(SecureClose) scb in
    print @String $ "Bob sent: " ^^ show @Int msg;
    let sca = secureSendInt msg @(SecureWait) sca in

    secureWait sca;
    secureClose scb

main : Int
main = 
    let (ca, dualca) = new @SecureMultiplication () in
    let (cb, dualcb) = new @SecureMultiplication () in
    fork @() (\_:() 1-> bob dualcb);
    fork @() (\_:() 1-> mallory dualca cb);
    alice 3 7 ca