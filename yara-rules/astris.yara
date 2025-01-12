rule Astris
{
    meta:
        author = "MalBeacon"
        description = "Astris system information file"
        reference = "https://github.com/MalBeacon/what-is-this-stealer"
    
    strings:
        $x1 = "[Network]" ascii
        $x2 = "Public IP Address:" ascii
        $x3 = "Internet Provider:" ascii
        $x4 = "Product Key:" ascii
        $x5 = "Antiviruses:" ascii
        $x6 = "[Machine]" ascii
        $x7 = "Build:" ascii

    condition:
        all of them
}