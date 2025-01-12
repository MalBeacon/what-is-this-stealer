rule Meduza
{
    meta:
        author = "MalBeacon"
        description = "Meduza system information file"
        reference = "https://github.com/MalBeacon/what-is-this-stealer"
    
    strings:
        $x1 = "HWID:" ascii
        $x2 = "Log Date:" ascii
        $x3 = "Build Name:" ascii
        $x4 = "Computer Name:" ascii
        $x5 = "Operation System:" ascii
        $x6 = "Execute Path:" ascii

    condition:
        all of them
}