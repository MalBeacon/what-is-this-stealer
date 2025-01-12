rule Noxy
{
    meta:
        author = "MalBeacon"
        description = "Noxy system information file"
        reference = "https://github.com/MalBeacon/what-is-this-stealer"
    
    strings:
        $x1 = "User:" ascii
        $x2 = "Process Executable Path:" ascii
        $x3 = "Uptime:" ascii
        $x4 = "ScreenResolution:" ascii
        $x5 = "Operating System:" ascii
        $x6 = "Disk Devices:" ascii

    condition:
        all of them
}