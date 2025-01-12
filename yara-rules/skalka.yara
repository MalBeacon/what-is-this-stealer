rule Skalka
{
    meta:
        author = "MalBeacon"
        description = "Skalka system information file"
        reference = "https://github.com/MalBeacon/what-is-this-stealer"
    
    strings:
        $x1 = "Operation System:" ascii
        $x2 = "Current JarFile Path:" ascii
        $x3 = "Width:" ascii
        $x4 = "UserName" ascii
        $x5 = "Language & Country:" ascii

    condition:
        all of them
}