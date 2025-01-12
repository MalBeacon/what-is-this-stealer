rule RedLine
{
    meta:
        author = "MalBeacon"
        description = "RedLine system information file"
        reference = "https://github.com/MalBeacon/what-is-this-stealer"
    
    strings:
        $x1 = "Build ID: " ascii
        $x2 = "FileLocation:" ascii
        $x3 = "UserName:" ascii
        $x4 = "MachineName:" ascii
        $x5 = "Log date:" ascii
        $x6 = "Hardwares:" ascii

    condition:
        all of them
}