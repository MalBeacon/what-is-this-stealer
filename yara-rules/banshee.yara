rule Banshee
{
    meta:
        author = "MalBeacon"
        description = "Banshee system information file"
        reference = "https://github.com/MalBeacon/what-is-this-stealer"
    
    strings:
        $x1 = "HWID:" ascii
        $x2 = "Log Date:" ascii
        $x3 = "Build Name:" ascii
        $x4 = "Country Code:" ascii
        $x5 = "User Name:" ascii
        $x6 = "Operation System:" ascii
        $y1 = "Screen Resolution:" ascii

    condition:
        ($x1 and $x2 and $x3 and $x4 and $x5 and $x6) and not $y1
}