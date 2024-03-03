use std::io::{self, Read, Cursor, Write};
use std::net::TcpStream;
use std::sync::{Arc, Mutex};

pub(crate) struct SharedConn {
    pub stream: TcpStream,
    buffer: Arc<Mutex<Cursor<Vec<u8>>>>,

    sni: String,
}

impl SharedConn {
    pub fn new(mut stream: TcpStream) -> Result<SharedConn, std::io::Error> {
        let buffer = Arc::new(Mutex::new(Cursor::new(Vec::new())));

        // read tls handshake from stream, and then put data into buffer
        let mut buf: [u8; 1024] = [0_u8; 1024];
        let n = stream.read(&mut buf)?;
        if n > 0 {
            let mut buffer = buffer.lock().unwrap();
            buffer.get_mut().extend_from_slice(&buf[..n]);
        }

        // 提取出 server name
        if n < 42 {
            return Err(io::Error::new(io::ErrorKind::Other, "tls handshake is too short"))
        }

        let mut m = ClientHello::new();

        //m.vers = (buf[4] << 8 | buf[5]) as u16;

        let session_id_len = buf[43] as usize;
        if n < 44+ session_id_len {
            return Err(io::Error::new(io::ErrorKind::Other, "tls handshake is too short"))
        }


        let mut cur = 44+ session_id_len;
        if n < cur+2 {
            return Err(io::Error::new(io::ErrorKind::Other, "tls handshake is too short"))
        }

        let cipher_suites_len = ((buf[cur] as usize) << 8 | buf[cur+1] as usize) as usize;
        if n < cur+2+ cipher_suites_len {
            return Err(io::Error::new(io::ErrorKind::Other, "tls handshake is too short"))
        }
        cur = cur + 2 + cipher_suites_len;


        let compression_methods_len = buf[cur] as usize;
        if n < cur+3+ cipher_suites_len + compression_methods_len {
            return Err(io::Error::new(io::ErrorKind::Other, "tls handshake is too short"))
        }

        cur = cur + 1 + compression_methods_len;

        let extension_len = (buf[cur] as usize) << 8 | (buf[cur+1] as usize);
        if n < cur+ extension_len {
            return Err(io::Error::new(io::ErrorKind::Other, "tls handshake is too short"))
        }

        cur = cur + 2;

        let mut ext_cur = 0;
        while ext_cur < extension_len {
            let ext_type = (buf[cur] as u16) << 8 | buf[cur+1] as u16;
            let ext_len = (buf[cur+2] as usize) << 8 | buf[cur+3] as usize;
            if ext_type == 0 {
                m.server_name = String::from_utf8(buf[cur+9..cur+4+ ext_len].to_vec()).unwrap();
                break;
            }
            cur += 4+ ext_len;
            ext_cur += 4+ ext_len;
        }


        Ok(SharedConn {
            stream,
            buffer,
            sni: m.server_name,
        })
    }

    pub fn get_sni(&self) -> String {
        self.sni.clone()
    }
}

impl Read for SharedConn {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let mut buffer = self.buffer.lock().unwrap();
        if buffer.position() < buffer.get_ref().len() as u64 {
            buffer.read(buf)
        } else {
            self.stream.read(buf)
        }
    }
}

impl Write for SharedConn {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.stream.write(buf)
    }

    // 实现flush方法
    fn flush(&mut self) -> io::Result<()> {
        // 同样，这里简单地将标准输出的缓冲区刷新，实际应用中应根据需要进行操作
       self.stream.flush()
    }
}


struct ClientHello {
    server_name: String,
}

impl ClientHello {
    pub fn new() -> ClientHello {
        ClientHello{
            server_name: "".to_string(),
        }
    }
}