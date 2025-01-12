rule RLStealer
{
    meta:
        author = "MalBeacon"
        description = "RLStealer system information file"
        reference = "https://github.com/MalBeacon/what-is-this-stealer"
    
    strings:
        $x1 = "==================================================" ascii
        $x2 = "ClipBoard :" ascii
        $x3 = "PC user :" ascii
        $x4 = "Current time :" ascii
        $x5 = "HWID :" ascii
        $x6 = "BSSID :" ascii

    condition:
        all of them
}