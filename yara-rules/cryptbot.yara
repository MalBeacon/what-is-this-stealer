rule CryptBot
{
    meta:
        author = "MalBeacon"
        description = "CryptBot system information file"
        reference = "https://github.com/MalBeacon/what-is-this-stealer"
    
    strings:
        $x1 = "UserName (ComputerName):" ascii
        $x2 = "Local Date and Time:" ascii
        $x3 = "OS:" ascii
        $x4 = "Display Resolution:" ascii
        $x5 = "RAM:" ascii
        $x6 = "GPU:" ascii

    condition:
        all of them
}