
$(document).ready(function () {
   $(".cart-button").on('click', function (event) {
       let id = $(this).data('id');
       if ($.cookie('cart') === undefined) {
           $.cookie('cart', JSON.stringify([]), { path:"/"});
       }
       let cart = JSON.parse($.cookie('cart'));
       cart.push([id, 1]);
       $.cookie('cart', JSON.stringify(cart), { path:"/"});

       document.getElementById('carticon').dataset.badge = JSON.parse($.cookie('cart')).length;
   });
   document.getElementById('carticon').dataset.badge = JSON.parse($.cookie('cart')).length;
});