rule Lumma
{
    meta:
        author = "MalBeacon"
        description = "Lumma system information file"
        reference = "https://github.com/MalBeacon/what-is-this-stealer"
    
    strings:
        $x1 = "- LummaC2 Build:" ascii
        $x2 = "- LID:" ascii
        $x3 = "- Configuration: " ascii
        $x4 = "- Display resolution:" ascii
        $x5 = "- HWID:" ascii
        $x6 = "- OS Version:" ascii

    condition:
        all of them
}