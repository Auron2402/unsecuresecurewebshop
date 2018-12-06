$(document).ready(function () {
    $(".admin-delete-button").on('click', function (event) {
        let id = $(this).data('id');
        location.href = '/ctf/admin/' + id + '/delete';
    });
    $('.admin-change-handling').on('click', function (event) {
        let mode = $(this).data('mode');
        $.ajax({
            method: 'GET',
            url: '/ctf/admin/changemode/' + mode,
            success: function (result) {
                // $("#" + mode + "-button").html('asdf');
                let id = mode + "-button";
                document.getElementById(id).textContent = result;
                console.log('asdf')
            }
        })
    })
});
