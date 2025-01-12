rule Raccoon2
{
    meta:
        author = "MalBeacon"
        description = "Raccoon2 system information file"
        reference = "https://github.com/MalBeacon/what-is-this-stealer"
    
    strings:
        $x1 = "System Information: " ascii
        $x2 = "User ID:" ascii
        $x3 = "Last seen:" ascii
        $x4 = "Build:" ascii
        $x5 = "IP info:" ascii
        $x6 = "Installed applications:" ascii

    condition:
        all of them
}