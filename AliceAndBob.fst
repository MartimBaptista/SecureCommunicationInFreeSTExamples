import SecureChannel

--Alice sends two values to bob, bob replies with productd of those values, all through secure channel

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

main : Int
main = forkWith @(SecureMultiplication) @() bob |> alice 3 7