# zip-luau
Blazingly Fast Luau module for encoding / decoding ZIP files

# Features
- Native codegen: `--!native`
- Strict typing: `--!strict`, full type annotations
- Blazingly fast: native codegen and buffer API gives maximum speed
- Both `ZIP32` and `ZIP64` support

# API
_Note: API for `zip32.luau` and `zip64.luau` are identical_

## `ZIP.Zip(Files: { [string]: buffer }, SearchDepth: number?) -> buffer`
Creates a ZIP archive (with an optional `SearchDepth` for `Deflate`) from files in format: `{ [file_path] = file_buffer }`
Returns ZIP archive buffer

## `ZIP.Unzip(Data: buffer) -> { [string]: buffer }`
Extracts files from ZIP archive
Returns extracted files in format: `{ [file_path] = file_buffer }`

## `ZIP.Deflate(Data: buffer, SearchDepth: number?) -> buffer`
Returns raw DEFLATE stream

## `ZIP.Inflate(Data: buffer, DecodedSize: number) -> buffer`
Returns decoded raw DEFLATE stream

## `ZIP.CRC32(Data: buffer) -> number`
Returns standart CRC32 for `Data` buffer

# Limitations
- Archive size limit is 1GB (Luau buffer size limit). The practical ZIP64 wins are more than 65535 entries and reading external ZIP64 archives
- `zip64.luau` requires the Luau `integer` library; `zip32.luau` has no such dependency

# Benchmarks
Measured with luau-cli, `--codegen` and `-O2`

| Operation | Speed |
| --- | --- |
| `Deflate` | 66–90 MB/s |
| `Inflate` | 286–720 MB/s |
| `CRC32` | 170 MB/s |
| `Zip` (write end-to-end) | 51–60 MB/s |

# Usage Examples

Creating a ZIP archive and extracting it with `zip32.luau`
```luau
const ZIP32 = require(path.to.zip32)

const Archive = ZIP32.Zip({
  ["folder/test.txt"] = buffer.fromstring("file contents")
})

const Extracted = ZIP32.Unzip(Archive)
print(Extracted) -- { ["folder/test.txt"] = buffer { Size = 13 } }

```

Creating a ZIP archive and extracting it with `zip64.luau`
```luau
const ZIP64 = require(path.to.zip64)

const Archive = ZIP64.Zip({
  ["folder/test.txt"] = buffer.fromstring("file contents")
})
-- API is the same!
const Extracted = ZIP64.Unzip(Archive)
print(Extracted) -- { ["folder/test.txt"] = buffer { Size = 13 } }

```
