package main

import (
    "bufio"
    "fmt"
    "os"
    "strings"
    "time"
    "math"
    "io"
    "flag"
)

func main() {
    var inputFilePath string
    var outputFilePath string
    var hibpFilePath string

    flag.StringVar(&inputFilePath, "input", "", "Specify input file containing hashed passwords")
    flag.StringVar(&outputFilePath, "output", "", "Specify output file for leaked hashes")
    flag.StringVar(&hibpFilePath, "hibp", "", "Specify Have I Been Pwned NTLM/SHA1 text file")

    flag.Parse()

    startTimer := time.Now()

    hibp, err := os.OpenFile(hibpFilePath, os.O_RDONLY, 0600)
    if err != nil {
        fmt.Println(err)
        return
    }

    hibpHashOnly, err := os.OpenFile("./temp_hashonly.txt", os.O_CREATE|os.O_RDWR|os.O_TRUNC, 0644)
    if err != nil {
        fmt.Println(err)
        return
    }

    hibpFileScanner := bufio.NewScanner(hibp)
    hibpHashOnlywriter := bufio.NewWriter(hibpHashOnly)

    for hibpFileScanner.Scan() {
        hash := strings.Split(hibpFileScanner.Text(), ":")[0]
        _, err := hibpHashOnlywriter.WriteString(hash + "\n")
        if err != nil {
            fmt.Printf("Got error while writing to a file. Err: %s", err.Error())
        }
    }

    hibpHashOnlywriter.Flush()
    hibp.Close()

    fmt.Printf("file converted with only hash in %s\n", time.Since(startTimer))

    hashs, err := os.Open(inputFilePath)
    if err != nil {
        fmt.Println(err)
        return
    }
    defer hashs.Close()

    leaked, err := os.OpenFile(outputFilePath, os.O_CREATE|os.O_RDWR|os.O_TRUNC, 0644)
    if err != nil {
        fmt.Println(err)
    }
    defer leaked.Close()

    hashCount := 1
    hashLeakedCount := 0

    hashsFileScanner := bufio.NewScanner(hashs)

    // read first line to determine size and type of hash
    hashsFileScanner.Scan()
    hash := strings.ToUpper(hashsFileScanner.Text())

    var hashLength int64 = int64(len(hash)) // 40 for SHA1 or 32 NTLM
    hashBuffer := make([]byte, hashLength)

    hibpHashOnlyStat, _ := hibpHashOnly.Stat()

    for hashsFileScanner.Scan() {
        var start int64 = 0
        var end int64 = hibpHashOnlyStat.Size()

        for {
            pos := start + ( int64(math.Floor(float64((end - start) / (hashLength + 1)) / 2 )) * (hashLength + 1) )

            hibpHashOnly.Seek(pos, io.SeekStart)

            hibpHashOnly.Read(hashBuffer)
            hashExtract := string(hashBuffer[:hashLength])

            //fmt.Printf("hash %s vs hashExtract %s\n", hash, hashExtract)

            if hash == hashExtract {
                leaked.WriteString(hashExtract + "\n")
                hashLeakedCount++
                //fmt.Printf("hash %s leaked\n", hash)
                break
            }

            if pos <= start || pos >= end {
                //fmt.Printf("hash %s didn't leaked\n", hash)
                break
            }

            if hash > hashExtract {
                start = pos
            } else {
                end = pos
            }
        }

        hash = strings.ToUpper(hashsFileScanner.Text())
        hashCount++
    }

    fmt.Printf("%d password hashs analyzed in %s and %d leaked\n", hashCount, time.Since(startTimer), hashLeakedCount)
}
