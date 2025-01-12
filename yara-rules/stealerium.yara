rule Stealerium
{
    meta:
        author = "MalBeacon"
        description = "Stealerium system information file"
        reference = "https://github.com/MalBeacon/what-is-this-stealer"
    
    strings:
        $x1 = "[IP]" ascii
        $x2 = "[Machine]" ascii
        $x3 = "[Virtualization]" ascii
        $x4 = "VirtualMachine:" ascii
        $x5 = "BATTERY:" ascii
        $x6 = "WEBCAMS COUNT:" ascii

    condition:
        all of them
}