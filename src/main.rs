mod modules;
use std::sync::Arc;

#[tokio::main]
async fn main() {
    // Create a new client and wrap it in an Arc (not in a Mutex)
    let client = Arc::new(
        modules::client::Client::new("148.113.191.144", 8081)
            .await
            .unwrap()
    );

    let client_for_on_message = Arc::clone(&client);
    let on_message = move |message: modules::client::Message| {
        println!("Doing stuff at least");
        println!("Received message from {}: {}", message.sender, message.content);

        let client_clone = Arc::clone(&client_for_on_message);
        tokio::spawn(async move {
            println!("Trying to send message");
            let dst_id_hexs = message.sender.clone();
            println!("Sending message to {}", dst_id_hexs);
            client_clone.send_message(&dst_id_hexs, message.content).await;
        });
    };

    // Call listen directly on the client (no outer lock)
    client.listen(on_message).await;
}
