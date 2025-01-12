rule BlankGrabber
{
    meta:
        author = "MalBeacon"
        description = "BlankGrabber system information file"
        reference = "https://github.com/MalBeacon/what-is-this-stealer"
    
    strings:
        $x1 = "Host Name:" ascii
        $x2 = "Registered Owner:" ascii
        $x3 = "Windows Directory:" ascii
        $x4 = "Domain:" ascii
        $x5 = "Logon Server:" ascii
        $x6 = "BIOS Version:" ascii

    condition:
        all of them
}