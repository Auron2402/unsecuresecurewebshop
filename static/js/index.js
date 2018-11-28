$(document).ready(function () {
    if ($.cookie('cart') == null) {
           $.cookie('cart', JSON.stringify([]), { path:"/"});
       }
    // $("#carticon").data('badge', JSON.parse($.cookie('cart')).length);

    document.getElementById('carticon').dataset.badge = JSON.parse($.cookie('cart')).length;
});