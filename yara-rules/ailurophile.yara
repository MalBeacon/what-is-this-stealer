rule Ailurophile
{
    meta:
        author = "MalBeacon"
        description = "Ailurophile system information file"
        reference = "https://github.com/MalBeacon/what-is-this-stealer"
    
    strings:
        $x1 = "Allowed Extensions:" ascii
        $x2 = "PC Type:" ascii
        $x3 = "Folders to Search:" ascii
        $x4 = "Screen Resolution:" ascii

    condition:
        all of them
}
