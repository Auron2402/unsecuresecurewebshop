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

    $('#checkflag-form').on('submit', function (event) {
        event.preventDefault();
        let flag = $('#checkflag-input').val();
        console.log(flag);
        $.ajax({
            method: 'POST',
            url: '/ctf/flag',
            data: $('#checkflag-form').serialize(),
            success: function (result) {
                console.log(result)
            }
        })
    })
});