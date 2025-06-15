//! Zero-Copy Streaming Interfaces
//!
//! Provides streaming interfaces that minimize memory allocations
//! and enable zero-copy operations for large archive processing.

use std::io::{Read, Write};
use std::fs::File;
use std::path::Path;
use std::collections::VecDeque;
use crate::error::{RuzipError, Result};

/// Zero-copy read trait for streaming operations
pub trait ZeroCopyRead {
    /// Read data without additional allocations
    fn read_zero_copy(&mut self, buf: &mut [u8]) -> Result<usize>;
    
    /// Advance the reader position without copying data
    fn advance(&mut self, count: usize) -> Result<()>;
    
    /// Get a slice of upcoming data without advancing position
    fn peek(&mut self, size: usize) -> Result<&[u8]>;
    
    /// Check if more data is available
    fn has_data(&self) -> bool;
    
    /// Get current position
    fn position(&self) -> u64;
}

/// Zero-copy write trait for streaming operations
pub trait ZeroCopyWrite {
    /// Write data without additional copying
    fn write_zero_copy(&mut self, data: &[u8]) -> Result<usize>;
    
    /// Flush any buffered data
    fn flush_zero_copy(&mut self) -> Result<()>;
    
    /// Reserve space for upcoming writes
    fn reserve(&mut self, size: usize) -> Result<()>;
    
    /// Get current write position
    fn position(&self) -> u64;
}

/// Chained buffer system for streaming without large allocations
pub struct ChainedBuffer {
    buffers: VecDeque<Vec<u8>>,
    current_read_buffer: usize,
    current_read_offset: usize,
    current_write_buffer: usize,
    current_write_offset: usize,
    buffer_size: usize,
    total_size: usize,
}

impl ChainedBuffer {
    /// Create new chained buffer with specified buffer size
    pub fn new(buffer_size: usize) -> Self {
        Self {
            buffers: VecDeque::new(),
            current_read_buffer: 0,
            current_read_offset: 0,
            current_write_buffer: 0,
            current_write_offset: 0,
            buffer_size,
            total_size: 0,
        }
    }

    /// Add new buffer to chain
    fn add_buffer(&mut self) {
        self.buffers.push_back(Vec::with_capacity(self.buffer_size));
    }

    /// Write data to chained buffer
    pub fn write(&mut self, data: &[u8]) -> Result<usize> {
        let mut written = 0;
        let mut remaining = data;

        while !remaining.is_empty() {
            // Ensure we have a write buffer
            if self.buffers.is_empty() || 
               self.current_write_buffer >= self.buffers.len() ||
               self.buffers[self.current_write_buffer].len() >= self.buffer_size {
                self.add_buffer();
                if self.buffers.len() > 1 {
                    self.current_write_buffer += 1;
                }
                self.current_write_offset = 0;
            }

            let buffer = &mut self.buffers[self.current_write_buffer];
            let available = self.buffer_size - buffer.len();
            let to_write = remaining.len().min(available);

            buffer.extend_from_slice(&remaining[..to_write]);
            remaining = &remaining[to_write..];
            written += to_write;
            self.total_size += to_write;
        }

        Ok(written)
    }

    /// Read data from chained buffer
    pub fn read(&mut self, buf: &mut [u8]) -> Result<usize> {
        let mut read = 0;
        let mut remaining = buf;

        while !remaining.is_empty() && self.current_read_buffer < self.buffers.len() {
            let buffer = &self.buffers[self.current_read_buffer];
            let available = buffer.len() - self.current_read_offset;
            
            if available == 0 {
                self.current_read_buffer += 1;
                self.current_read_offset = 0;
                continue;
            }

            let to_read = remaining.len().min(available);
            let src = &buffer[self.current_read_offset..self.current_read_offset + to_read];
            remaining[..to_read].copy_from_slice(src);
            
            remaining = &mut remaining[to_read..];
            read += to_read;
            self.current_read_offset += to_read;
        }

        Ok(read)
    }

    /// Peek at upcoming data without advancing position
    pub fn peek(&self, size: usize) -> Result<Vec<u8>> {
        let mut result = Vec::with_capacity(size);
        let mut remaining = size;
        let mut buffer_idx = self.current_read_buffer;
        let mut offset = self.current_read_offset;

        while remaining > 0 && buffer_idx < self.buffers.len() {
            let buffer = &self.buffers[buffer_idx];
            let available = buffer.len() - offset;
            
            if available == 0 {
                buffer_idx += 1;
                offset = 0;
                continue;
            }

            let to_copy = remaining.min(available);
            result.extend_from_slice(&buffer[offset..offset + to_copy]);
            remaining -= to_copy;
            offset += to_copy;
        }

        Ok(result)
    }

    /// Get total size of data in buffer
    pub fn len(&self) -> usize {
        self.total_size - self.bytes_read()
    }

    /// Check if buffer is empty
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Get number of bytes read
    pub fn bytes_read(&self) -> usize {
        let mut read = 0;
        for i in 0..self.current_read_buffer {
            if i < self.buffers.len() {
                read += self.buffers[i].len();
            }
        }
        read + self.current_read_offset
    }

    /// Reset buffer for reuse
    pub fn reset(&mut self) {
        self.buffers.clear();
        self.current_read_buffer = 0;
        self.current_read_offset = 0;
        self.current_write_buffer = 0;
        self.current_write_offset = 0;
        self.total_size = 0;
    }
}

/// Zero-copy reader implementation
pub struct ZeroCopyReader<R: Read> {
    inner: R,
    buffer: Vec<u8>,
    buffer_pos: usize,
    buffer_len: usize,
    position: u64,
}

impl<R: Read> ZeroCopyReader<R> {
    /// Create new zero-copy reader
    pub fn new(inner: R, buffer_size: usize) -> Self {
        Self {
            inner,
            buffer: vec![0; buffer_size],
            buffer_pos: 0,
            buffer_len: 0,
            position: 0,
        }
    }

    /// Fill internal buffer
    fn fill_buffer(&mut self) -> Result<()> {
        if self.buffer_pos >= self.buffer_len {
            self.buffer_len = self.inner.read(&mut self.buffer)
                .map_err(|e| RuzipError::io_error("Read failed", e))?;
            self.buffer_pos = 0;
        }
        Ok(())
    }

    /// Get available data in buffer
    fn available(&self) -> &[u8] {
        &self.buffer[self.buffer_pos..self.buffer_len]
    }
}

impl<R: Read> ZeroCopyRead for ZeroCopyReader<R> {
    fn read_zero_copy(&mut self, buf: &mut [u8]) -> Result<usize> {
        self.fill_buffer()?;
        
        let available = self.available();
        let to_copy = buf.len().min(available.len());
        
        if to_copy > 0 {
            buf[..to_copy].copy_from_slice(&available[..to_copy]);
            self.buffer_pos += to_copy;
            self.position += to_copy as u64;
        }
        
        Ok(to_copy)
    }

    fn advance(&mut self, count: usize) -> Result<()> {
        let mut remaining = count;
        
        while remaining > 0 {
            self.fill_buffer()?;
            let available = self.buffer_len - self.buffer_pos;
            
            if available == 0 {
                break; // EOF
            }
            
            let to_skip = remaining.min(available);
            self.buffer_pos += to_skip;
            self.position += to_skip as u64;
            remaining -= to_skip;
        }
        
        Ok(())
    }

    fn peek(&mut self, size: usize) -> Result<&[u8]> {
        self.fill_buffer()?;
        let available = self.available();
        Ok(&available[..size.min(available.len())])
    }

    fn has_data(&self) -> bool {
        self.buffer_pos < self.buffer_len
    }

    fn position(&self) -> u64 {
        self.position
    }
}

/// Zero-copy writer implementation
pub struct ZeroCopyWriter<W: Write> {
    inner: W,
    buffer: Vec<u8>,
    position: u64,
    buffer_size: usize,
}

impl<W: Write> ZeroCopyWriter<W> {
    /// Create new zero-copy writer
    pub fn new(inner: W, buffer_size: usize) -> Self {
        Self {
            inner,
            buffer: Vec::with_capacity(buffer_size),
            position: 0,
            buffer_size,
        }
    }

    /// Flush internal buffer
    fn flush_internal(&mut self) -> Result<()> {
        if !self.buffer.is_empty() {
            self.inner.write_all(&self.buffer)
                .map_err(|e| RuzipError::io_error("Write failed", e))?;
            self.buffer.clear();
        }
        Ok(())
    }
}

impl<W: Write> ZeroCopyWrite for ZeroCopyWriter<W> {
    fn write_zero_copy(&mut self, data: &[u8]) -> Result<usize> {
        // If data is larger than buffer, write directly
        if data.len() > self.buffer_size {
            self.flush_internal()?;
            self.inner.write_all(data)
                .map_err(|e| RuzipError::io_error("Write failed", e))?;
            self.position += data.len() as u64;
            return Ok(data.len());
        }

        // If buffer would overflow, flush first
        if self.buffer.len() + data.len() > self.buffer_size {
            self.flush_internal()?;
        }

        // Add to buffer
        self.buffer.extend_from_slice(data);
        self.position += data.len() as u64;
        Ok(data.len())
    }

    fn flush_zero_copy(&mut self) -> Result<()> {
        self.flush_internal()?;
        self.inner.flush().map_err(|e| RuzipError::io_error("Flush failed", e))?;
        Ok(())
    }

    fn reserve(&mut self, size: usize) -> Result<()> {
        if self.buffer.capacity() - self.buffer.len() < size {
            self.flush_internal()?;
            if self.buffer.capacity() < size {
                self.buffer.reserve(size - self.buffer.capacity());
            }
        }
        Ok(())
    }

    fn position(&self) -> u64 {
        self.position
    }
}

/// Memory-mapped archive for zero-copy access to large files
pub struct MemoryMappedArchive {
    #[cfg(unix)]
    mapping: memmap2::Mmap,
    #[cfg(not(unix))]
    _file: File,
    #[cfg(not(unix))]
    data: Vec<u8>,
    header_offset: usize,
    entries_offset: usize,
    data_offset: usize,
}

impl MemoryMappedArchive {
    /// Create memory-mapped archive from file
    pub fn new<P: AsRef<Path>>(path: P) -> Result<Self> {
        let file = File::open(path).map_err(|e| RuzipError::io_error("Failed to open file", e))?;
        
        #[cfg(unix)]
        {
            use memmap2::MmapOptions;
            let mapping = unsafe {
                MmapOptions::new()
                    .map(&file)
                    .map_err(|e| RuzipError::io_error("Memory mapping failed", e))?
            };

            // Parse header to get offsets
            let (header_offset, entries_offset, data_offset) = Self::parse_offsets(&mapping)?;

            Ok(Self {
                mapping,
                header_offset,
                entries_offset,
                data_offset,
            })
        }

        #[cfg(not(unix))]
        {
            use std::io::Read;
            let mut data = Vec::new();
            let mut file = file;
            file.read_to_end(&mut data).map_err(|e| RuzipError::io_error("Failed to read file", e))?;

            let (header_offset, entries_offset, data_offset) = Self::parse_offsets(&data)?;

            Ok(Self {
                _file: File::open(path).map_err(|e| RuzipError::io_error("Failed to open file", e))?,
                data,
                header_offset,
                entries_offset,
                data_offset,
            })
        }
    }

    /// Parse archive structure to find offsets
    fn parse_offsets(data: &[u8]) -> Result<(usize, usize, usize)> {
        if data.len() < 16 {
            return Err(RuzipError::invalid_archive("Archive too small", None));
        }

        // Simple offset parsing - in real implementation this would
        // parse the actual archive header format
        let header_offset = 0;
        let entries_offset = 64; // Placeholder
        let data_offset = 1024;   // Placeholder

        Ok((header_offset, entries_offset, data_offset))
    }

    /// Get archive data slice
    pub fn data(&self) -> &[u8] {
        #[cfg(unix)]
        {
            &self.mapping
        }
        #[cfg(not(unix))]
        {
            &self.data
        }
    }

    /// Get header slice without copying
    pub fn header_slice(&self) -> Result<&[u8]> {
        let data = self.data();
        if self.header_offset + 64 > data.len() {
            return Err(RuzipError::invalid_archive("Invalid header offset", None));
        }
        Ok(&data[self.header_offset..self.header_offset + 64])
    }

    /// Get entries table slice without copying
    pub fn entries_slice(&self) -> Result<&[u8]> {
        let data = self.data();
        if self.entries_offset >= data.len() || self.data_offset <= self.entries_offset {
            return Err(RuzipError::invalid_archive("Invalid entries offset", None));
        }
        Ok(&data[self.entries_offset..self.data_offset])
    }

    /// Get file data slice by offset and size
    pub fn file_data_slice(&self, offset: u64, size: u64) -> Result<&[u8]> {
        let data = self.data();
        let start = self.data_offset + offset as usize;
        let end = start + size as usize;
        
        if end > data.len() {
            return Err(RuzipError::invalid_archive("File data out of bounds", None));
        }
        
        Ok(&data[start..end])
    }

    /// Create zero-copy reader for specific file
    pub fn file_reader(&self, offset: u64, size: u64) -> Result<MemorySliceReader> {
        let slice = self.file_data_slice(offset, size)?;
        Ok(MemorySliceReader::new(slice))
    }

    /// Get total archive size
    pub fn size(&self) -> usize {
        self.data().len()
    }
}

/// Zero-copy reader for memory slices
pub struct MemorySliceReader<'a> {
    data: &'a [u8],
    position: usize,
}

impl<'a> MemorySliceReader<'a> {
    /// Create new memory slice reader
    pub fn new(data: &'a [u8]) -> Self {
        Self { data, position: 0 }
    }
}

impl<'a> ZeroCopyRead for MemorySliceReader<'a> {
    fn read_zero_copy(&mut self, buf: &mut [u8]) -> Result<usize> {
        let available = &self.data[self.position..];
        let to_copy = buf.len().min(available.len());
        
        if to_copy > 0 {
            buf[..to_copy].copy_from_slice(&available[..to_copy]);
            self.position += to_copy;
        }
        
        Ok(to_copy)
    }

    fn advance(&mut self, count: usize) -> Result<()> {
        self.position = (self.position + count).min(self.data.len());
        Ok(())
    }

    fn peek(&mut self, size: usize) -> Result<&[u8]> {
        let available = &self.data[self.position..];
        Ok(&available[..size.min(available.len())])
    }

    fn has_data(&self) -> bool {
        self.position < self.data.len()
    }

    fn position(&self) -> u64 {
        self.position as u64
    }
}

impl<'a> Read for MemorySliceReader<'a> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        self.read_zero_copy(buf).map_err(|e| {
            std::io::Error::new(std::io::ErrorKind::Other, e.to_string())
        })
    }
}

/// Streaming buffer that reuses memory
pub struct StreamingBuffer {
    primary: Vec<u8>,
    secondary: Vec<u8>,
    active_primary: bool,
    read_pos: usize,
    write_pos: usize,
}

impl StreamingBuffer {
    /// Create new streaming buffer
    pub fn new(size: usize) -> Self {
        Self {
            primary: Vec::with_capacity(size),
            secondary: Vec::with_capacity(size),
            active_primary: true,
            read_pos: 0,
            write_pos: 0,
        }
    }

    /// Get active write buffer
    pub fn write_buffer(&mut self) -> &mut Vec<u8> {
        if self.active_primary {
            &mut self.primary
        } else {
            &mut self.secondary
        }
    }

    /// Get active read buffer
    pub fn read_buffer(&self) -> &Vec<u8> {
        if self.active_primary {
            &self.secondary
        } else {
            &self.primary
        }
    }

    /// Swap buffers for double-buffering
    pub fn swap_buffers(&mut self) {
        self.active_primary = !self.active_primary;
        self.read_pos = 0;
        self.write_pos = 0;
        
        // Clear the new write buffer
        self.write_buffer().clear();
    }

    /// Read from current read buffer
    pub fn read(&mut self, buf: &mut [u8]) -> usize {
        let read_buf = self.read_buffer();
        let available = read_buf.len() - self.read_pos;
        let to_copy = buf.len().min(available);
        
        if to_copy > 0 {
            buf[..to_copy].copy_from_slice(&read_buf[self.read_pos..self.read_pos + to_copy]);
            self.read_pos += to_copy;
        }
        
        to_copy
    }

    /// Write to current write buffer
    pub fn write(&mut self, data: &[u8]) -> usize {
        let write_buf = self.write_buffer();
        let available = write_buf.capacity() - write_buf.len();
        let to_write = data.len().min(available);
        
        if to_write > 0 {
            write_buf.extend_from_slice(&data[..to_write]);
        }
        
        to_write
    }

    /// Check if read buffer has data
    pub fn has_read_data(&self) -> bool {
        self.read_pos < self.read_buffer().len()
    }

    /// Check if write buffer has space
    pub fn has_write_space(&self) -> bool {
        let buffer = if self.active_primary {
            &self.primary
        } else {
            &self.secondary
        };
        buffer.len() < buffer.capacity()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn test_chained_buffer() {
        let mut buffer = ChainedBuffer::new(10);
        
        // Write data across multiple buffers
        buffer.write(b"hello").unwrap();
        buffer.write(b"world").unwrap();
        buffer.write(b"test").unwrap();
        
        assert_eq!(buffer.len(), 14);
        
        // Read data back
        let mut read_buf = [0u8; 20];
        let read = buffer.read(&mut read_buf).unwrap();
        assert_eq!(read, 14);
        assert_eq!(&read_buf[..14], b"helloworldtest");
    }

    #[test]
    fn test_zero_copy_reader() {
        let data = b"hello world test data";
        let cursor = Cursor::new(data);
        let mut reader = ZeroCopyReader::new(cursor, 8);
        
        let mut buf = [0u8; 5];
        let read = reader.read_zero_copy(&mut buf).unwrap();
        assert_eq!(read, 5);
        assert_eq!(&buf, b"hello");
        
        reader.advance(1).unwrap(); // Skip space
        
        let mut buf2 = [0u8; 5];
        let read = reader.read_zero_copy(&mut buf2).unwrap();
        assert_eq!(read, 2); // Only "wo" left after advance(1)
        assert_eq!(&buf2[..read], b"wo");
    }

    #[test]
    fn test_zero_copy_writer() {
        let mut output = Vec::new();
        let mut writer = ZeroCopyWriter::new(&mut output, 8);
        
        writer.write_zero_copy(b"hello").unwrap();
        writer.write_zero_copy(b" ").unwrap();
        writer.write_zero_copy(b"world").unwrap();
        writer.flush_zero_copy().unwrap();
        
        assert_eq!(output, b"hello world");
    }

    #[test]
    fn test_memory_slice_reader() {
        let data = b"test data for reading";
        let mut reader = MemorySliceReader::new(data);
        
        let mut buf = [0u8; 4];
        let read = reader.read_zero_copy(&mut buf).unwrap();
        assert_eq!(read, 4);
        assert_eq!(&buf, b"test");
        
        reader.advance(1).unwrap(); // Skip space
        
        let peek_data = reader.peek(4).unwrap();
        assert_eq!(peek_data, b"data");
        
        assert_eq!(reader.position(), 5);
    }

    #[test]
    fn test_streaming_buffer() {
        let mut buffer = StreamingBuffer::new(10);
        
        // Write to primary buffer
        let written = buffer.write(b"hello");
        assert_eq!(written, 5);
        
        // Swap to secondary for reading
        buffer.swap_buffers();
        
        // Write to new primary while reading from secondary
        buffer.write(b"world");
        
        let mut read_buf = [0u8; 10];
        let read = buffer.read(&mut read_buf);
        assert_eq!(read, 5);
        assert_eq!(&read_buf[..5], b"hello");
    }
}