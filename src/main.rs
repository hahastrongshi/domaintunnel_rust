mod shared;
mod tls;

use std::io;
use std::thread;
use std::net::{TcpListener, TcpStream};

// 创建一个 TLS 代理服务
fn main() {
    // 创建一个 TLS 代理服务并指定端口
    let tls_listener = TcpListener::bind("0.0.0.0:443").unwrap();

    for stream in tls_listener.incoming() {
        match stream {
            Ok( stream) => {

                // 从接收的 socket 中读取 sni 信息
                let mut tls_conn = tls::TlsConn::new(stream).unwrap();
                //let sni = read_sni(&mut stream);
                let sni = tls_conn.get_sni();
                if !is_allowed(&sni) {
                    eprintln!("not allowed: {}", sni);
                    tls_conn.close();
                    continue
                }
                let target_addr = format!("{}:443", sni);

                // 根据 sni 信息创建一个新的 socket
               match TcpStream::connect(target_addr) {
                   Ok(mut tcp_stream) => {
                       let mut stream_clone = tls_conn.shared_conn.stream.try_clone().unwrap();
                       let mut tcp_stream_clone = tcp_stream.try_clone().unwrap();

                       thread::spawn(move || {
                           let _ = io::copy(&mut tcp_stream_clone, &mut stream_clone);
                           println!("copy tcp_stream to stream 1");
                       });

                       thread::spawn(move || {
                           let _ = io::copy(&mut tls_conn.shared_conn, &mut tcp_stream);
                           println!("copy stream to tcp_stream 2");
                       });

                   }
                   Err(e) => eprintln!("failed : {}", e),
               }

            }

            Err(e) => {
                eprintln!("failed: {}", e)
            }
        }
    }
}

fn is_allowed(domain: &str) -> bool {
    println!("is_allowed: {}", domain);
    true
}