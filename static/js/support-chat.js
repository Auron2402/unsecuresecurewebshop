let last_message_id = 0;

$(document).ready(function () {
    regular_check_message()

    $('#message_input').keyup(function (event) {
        if (event.key === 'Enter') {
            //on enter send message
            let inputfield = $('#message_input')
            send_message(inputfield.val())
            //clear input
            inputfield.val('')
        }
    })
});


function query_messages() {
    //get information
    $.getJSON('/api/get_message_after', {
            last_message_id: last_message_id
        }, function (data) {
            // if new messages, add to message UI
            if (data !== []) {
                data.forEach(message => {
                    add_message_to_ui(message);

                })

            }

            // set last message so only new messages will be updated
            let last_message_item = data.pop();
            if (last_message_item !== undefined) last_message_id = last_message_item[0]
        }
    )
}

function add_message_to_ui(messageObject) {
    // read object
    let id = messageObject[0]
    let message = messageObject[1]
    let sender_id = messageObject[2]

    // add time to look more "chaty"
    let date = formatAMPM(new Date());
    let message_html = '';
    let data_div = $('.last_message_sent_by')
    //create html
    console.log(sender_id)
    if (sender_id === 184) {
        message_html = '<li class="mdl-list__item" style="width:100%;">' +
            '<div class="msj-rta macro">' +
            '<div class="text text-r">' +
            '<p>' + message + '</p>' +
            '<p><small>' + date + '</small></p>' +
            '</div>' +
            '<div class="avatar" style="padding:0px 0px 0px 10px !important"></div>' +
            '</li>';
        console.log('change data to support');
        data_div.attr('data-user', 'support');
    } else {
        message_html = '<li class="mdl-list__item" style="width:100%">' +
            '<div class="msj macro">' +
            '<div class="text text-l">' +
            '<p>' + message + '</p>' +
            '<p><small>' + date + '</small></p>' +
            '</div>' +
            '</div>' +
            '</li>';
        console.log('change data to user');
        data_div.attr('data-user', 'user');
    }
    // add html to UI
    let scrolldiv = $('#chat_message_list');

    scrolldiv.append(message_html)
    // scroll to last message
    scrolldiv.animate({scrollTop: scrolldiv.prop('scrollHeight')}, 50);
}


function send_message(text) {
    //send message to db
    $.getJSON('/api/send_message', {
            message_text: text
        }, function (data) {
            console.log(data)
        }
    )
    //update chat
    query_messages()
}

function formatAMPM(date) {
    let hours = date.getHours();
    let minutes = date.getMinutes();
    let ampm = hours >= 12 ? 'PM' : 'AM';
    hours = hours % 12;
    hours = hours ? hours : 12; // the hour '0' should be '12'
    minutes = minutes < 10 ? '0' + minutes : minutes;
    return hours + ':' + minutes + ' ' + ampm;
}

// check for new message every 2 sec
async function regular_check_message() {
    // noinspection InfiniteLoopJS
    while (true) {
        query_messages();
        await sleep(1000)
    }
}

function sleep(ms) {
    return new Promise(resolve => setTimeout(resolve, ms));
}