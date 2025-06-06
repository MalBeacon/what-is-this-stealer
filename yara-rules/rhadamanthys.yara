rule Rhadamanthys
{
    meta:
        author = "megansquire"
        description = "Rhadamanthys Stealer system information file"
        reference = "https://github.com/MalBeacon/what-is-this-stealer"
    
    strings:
        $s1 = "Install Date:" ascii
        $s2 = "Traffic Name:" ascii
        $s3 = "HWID:" ascii
        $s4 = "User Name:" ascii
        $s5 = "WallPaper Hash:" ascii
        
    condition:
        all of them
}
