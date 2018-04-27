/**
 * Copyright 2018-present, Grand Valley State University
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
use std::net::TcpListener;
use std::net::TcpStream;
use std::io::prelude::*;
use std::io::Write;

fn cert_validation(request: String) -> bool {

}

fn handle_connection(mut stream: TcpStream) {
    // TODO - Add buffer management for larger sized requests
    let mut buffer = [0; 512];
    // TODO - Add error handling
    stream.read(&mut buffer).unwrap();

    // Store the request data to forward to the DB
    let request = String::from_utf8_lossy(&buffer);

    // Successful request
    // Placeholder response string
    let response = "HTTP/1.1 200 OK\r\n\r\n";

    // Write the response back out to the requesting server
    // TODO - Add error handling
    stream.write(response.as_bytes()).unwrap();
    stream.flush().unwrap();
}

fn main () {
    let port = "8000";
    let listener = TcpListener::bind(format!("127.0.0.1:{}", port)).unwrap();
    writeln!(std::io::stdout(), "Server running on port: {}", port).unwrap();

    for stream in listener.incoming() {
        let stream = stream.unwrap();

        handle_connection(stream);
    }
}
