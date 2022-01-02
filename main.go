package main

import (
    "bufio"
    "fmt"
    "os"
    "strings"
    "time"
    "math"
    "io"
)

func main() {

    startTimer := time.Now()

    hibp, err := os.OpenFile("./pwned-passwords-sha1-ordered-by-hash-v8.txt", os.O_RDONLY, 0600)
    if err != nil {
        fmt.Println(err)
        return
    }

    hibpHashOnly, err := os.OpenFile("./pwned-passwords-sha1-ordered-by-hash-v8-hashonly.txt", os.O_CREATE|os.O_RDWR|os.O_TRUNC, 0644)
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

    hashs, err := os.Open("./hashs.txt")
    if err != nil {
        fmt.Println(err)
        return
    }
    defer hashs.Close()

    leaked, err := os.OpenFile("./leaked_hashs.txt", os.O_CREATE|os.O_RDWR|os.O_TRUNC, 0644)
    if err != nil {
        fmt.Println(err)
    }
    defer leaked.Close()

    const hashLength int64 = 40
    hashBuffer := make([]byte, hashLength)

    hashCount := 0
    hashLeakedCount := 0

    hibpHashOnlyStat, _ := hibpHashOnly.Stat()

    hashsFileScanner := bufio.NewScanner(hashs)
    for hashsFileScanner.Scan() {
        hash := strings.ToUpper(hashsFileScanner.Text())

        var start int64 = 0
        var end int64 = hibpHashOnlyStat.Size()

        hashCount++

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
    }

    fmt.Printf("%d password hashs analyzed in %s and %d leaked\n", hashCount, time.Since(startTimer), hashLeakedCount)
}
