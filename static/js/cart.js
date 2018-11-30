$(document).ready(function () {
    //onbutton delete element from cart
    $(".deletebutton").on('click', function (event) {
       let position = $(this).data('position');
       let cart = JSON.parse($.cookie('cart'));
       if($('td:contains("GESAMT")').data('id') === position) {
           console.log("completewipe");
           $.cookie('cart', JSON.stringify([]), { path:"/"});
           location.reload();
           return null;
       }
       cart.splice(position - 1, 1);
       $.cookie('cart', JSON.stringify(cart), { path:"/"});
       location.reload();
    });
});