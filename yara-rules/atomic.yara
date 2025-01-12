rule Atomic
{
    meta:
        author = "MalBeacon"
        description = "Atomic system information file"
        reference = "https://github.com/MalBeacon/what-is-this-stealer"
    
    strings:
        $x1 = "Userinfo:" ascii
        $x2 = "MetaMask Info:" ascii
        $x3 = "Private Keys:" ascii
        $x4 = "Debanks:" ascii
        $x5 = "ProductName:        macOS" ascii
        $x6 = "BuildVersion:" ascii

    condition:
        all of them
}