rule Luca
{
    meta:
        author = "MalBeacon"
        description = "Luca system information file"
        reference = "https://github.com/MalBeacon/what-is-this-stealer"
    
    strings:
        $x1 = "- IP Info -" ascii
        $x2 = "- PC Info -" ascii
        $x3 = "Antivirus:" ascii
        $x4 = "- Other Info -" ascii
        $x5 = "- Log Info -" ascii
        $x6 = "FileLocation:" ascii

    condition:
        all of them
}