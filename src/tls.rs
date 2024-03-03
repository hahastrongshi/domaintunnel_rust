use std::net::TcpStream;
use std::net;
use crate::shared::SharedConn;

pub(crate) struct TlsConn {
    pub shared_conn: SharedConn,
}

impl TlsConn {
    pub(crate) fn new(conn: TcpStream) -> Result<TlsConn, ()> {
        let Ok(shared_conn) = SharedConn::new(conn) else {
            return Err(());
        };
        // let clientHello = ClientHello::new(shared_conn);
        //let _sni = get_sni(_reader);
        Ok(TlsConn {
            shared_conn: shared_conn,
        })
    }

    pub fn get_sni(&self) -> String {
        self.shared_conn.get_sni()
    }

    pub fn close(&self) {
        self.shared_conn.stream.shutdown(net::Shutdown::Both).unwrap()
    }
}
