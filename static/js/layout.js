let dialog = document.querySelector('.ctf-panel-dialog');
let showModalButton = document.querySelector('#ctf-panel-button');
if (!dialog.showModal) {
    dialogPolyfill.registerDialog(dialog);
}
showModalButton.addEventListener('click', function () {
    dialog.showModal();
});
dialog.querySelector('.close').addEventListener('click', function () {
    dialog.close();
});

$(document).ready(function () {
    $('#ctf-panel-reset-button').on('click', function (event) {
        event.preventDefault();
        let really = window.confirm('Bist du dir Sicher, dass du den Server Zurücksetzten willst?');
        if(really === true) {
            location.href = '/ctf/reset'
        } else {
            return null
        }
    });

    $('.tip-button').on('click', function (event) {
        event.preventDefault();
        let index = $(this).data('index');
        let thema = $(this).data('thema');
        let tipdiv = document.getElementById(thema + "-" + index);
        if (tipdiv.style.display === "none") {
            tipdiv.style.display = "block";
        } else {
            tipdiv.style.display = "none";
        }
    });

    $('.thema-button').on('click', function (event) {
        event.preventDefault();
        let index = $(this).data('index');
        let themadiv = document.getElementById("thema-" + index);
        if (themadiv.style.display === "none") {
            themadiv.style.display = "block";
        } else {
            themadiv.style.display = "none";
        }
    });



});