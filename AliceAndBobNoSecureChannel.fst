type Multiplication = !Int ; !Int ; ?Int ; Close

alice : Int -> Int -> Multiplication -> Int 
alice n m c =
    let c = send n c in
    let c = send m c in
    let (res, c) = receive c in
    close c;
    res

bob : dualof Multiplication -> ()
bob c =
    let (n, c) = receive c in
    let (m, c) = receive c in
    let c = send (n*m) c in
    wait c

main : Int
main = forkWith @(Multiplication) @() bob |> alice 3 7