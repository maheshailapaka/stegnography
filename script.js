$(document).ready(function () {
    $('#encryptForm').submit(function (e) {
        e.preventDefault();
        let formData = new FormData();
        formData.append('image', $('#encryptImage')[0].files[0]);
        formData.append('message', $('#message').val());
        formData.append('password', $('#encryptPassword').val());

        fetch('/encrypt', { method: 'POST', body: formData })
            .then(response => response.blob())
            .then(blob => {
                let url = window.URL.createObjectURL(blob);
                let a = document.createElement('a');
                a.href = url;
                a.download = 'encrypted_image.png';
                document.body.appendChild(a);
                a.click();
                a.remove();
            });
    });

    $('#decryptForm').submit(function (e) {
        e.preventDefault();
        let formData = new FormData();
        formData.append('image', $('#decryptImage')[0].files[0]);
        formData.append('password', $('#decryptPassword').val());

        fetch('/decrypt', { method: 'POST', body: formData })
            .then(response => response.json())
            .then(data => $('#decryptedMessage').text("Decrypted Message: " + data.message))
            .catch(() => alert("Decryption failed"));
    });
});  