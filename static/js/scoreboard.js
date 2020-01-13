$(document).ready(function () {
        $('#checkflag-form').on('submit', function (event) {
            event.preventDefault();
            let flag = $('#checkflag-input').val();
            $.ajax({
                method: 'GET',
                url: '/ctf/flag/' + flag,
                success: function (result) {
                    if (result === true) {
                        $('#flag-result-div').html('<div class="alert alert-success" role="alert">\n' +
                            '  <button type="button" class="close-alert">×</button>\n' +
                            '  <i class="material-icons">warning</i>\n' +
                            '  Die Flagge ist Korrekt! Glückwunsch' +
                            '</div>');
                        $(".close-alert").on('click', function (e) {
                            $(this).parent().remove();
                            e.preventDefault();
                        });
                    } else {
                        $('#flag-result-div').html('<div class="alert alert-danger" role="alert">\n' +
                            '  <button type="button" class="close-alert">×</button>\n' +
                            '  <i class="material-icons">error</i>\n' +
                            '  Die Flagge ist Falsch, versuchs noch einmal' +
                            '</div>');
                        $(".close-alert").on('click', function (e) {
                            $(this).parent().remove();
                            e.preventDefault();
                        });
                    }

                }
            })
        });


        let timestamp = $('#timestamp').data('timestamp');
        let startTimestamp = Date.parse(timestamp);
        let stopwatchInterval, elapsedTime = 0;


        setInterval(function () {
            elapsedTime = Date.now() - startTimestamp;
            update_time(elapsedTime)
        }, 1000)

    }
);

var timerValueObj = $("#timer-value");

function update_time(tempTime) {
    tempTime = Math.floor(tempTime / 1000);
    let seconds = tempTime % 60;
    tempTime = Math.floor(tempTime / 60);
    let minutes = tempTime % 60;
    tempTime = Math.floor(tempTime / 60);
    let hours = tempTime % 60;

    var time = hours + " : " + minutes + " : " + seconds;
    timerValueObj.text(time);
}
