rule ArechClientV2
{
    meta:
        author = "MalBeacon"
        description = "ArechClientV2 system information file"
        reference = "https://github.com/MalBeacon/what-is-this-stealer"
    
    strings:
        $x1 = "FileLocation:" ascii
        $x2 = "HWID:" ascii
        $x3 = "Available KeyboardLayouts:" ascii
        $x4 = "Hardwares:" ascii
        $y1 = "MachineName:" ascii

    condition:
        ($x1 and $x2 and $x3 and $x4) and not $y1
}