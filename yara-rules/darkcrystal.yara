rule DarkCrystal
{
    meta:
        author = "MalBeacon"
        description = "DarkCrystal system information file"
        reference = "https://github.com/MalBeacon/what-is-this-stealer"
    
    strings:
        $x1 = "Monitors:" ascii
        $x2 = "Save Time:" ascii
        $x3 = "LANIP:" ascii
        $x4 = ".NET Framework Version:" ascii

    condition:
        all of them
}