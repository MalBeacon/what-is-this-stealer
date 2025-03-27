rule PredatorTheThiefv3
{
    meta:
        author = "Davide Ciacciolo"
        description = "PredatorTheThief v3 system information file"
        reference = "https://github.com/MalBeacon/what-is-this-stealer"
    
    strings:
        $x1 = "Launch time:" ascii
        $x2 = "Startup folder:" ascii
        $x3 = "Amount of kernels:" ascii
        $x4 = "GPU info:" ascii
        $x5 = "Amount of RAM:" ascii

    condition:
        all of them
}