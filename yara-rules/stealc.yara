rule StealC
{
    meta:
        author = "MalBeacon"
        description = "StealC system information file"
        reference = "https://github.com/MalBeacon/what-is-this-stealer"
    
    strings:
        $x1 = "- HWID:" ascii
        $x2 = "Network Info:" ascii
        $x3 = "- UserName:" ascii
        $x4 = "- Running Path:" ascii
        $x5 = "- Cores:" ascii
        $x6 = "- Display Resolution:" ascii

    condition:
        all of them
}