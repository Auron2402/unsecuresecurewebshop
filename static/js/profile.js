let profiledialog = document.querySelector('.profile-dialog');
let profileshowModalButton = document.querySelector('.show-modal');
if (!profiledialog.showModal) {
    dialogPolyfill.registerDialog(profiledialog);
}
profileshowModalButton.addEventListener('click', function () {
    profiledialog.showModal();
});
profiledialog.querySelector('.close').addEventListener('click', function () {
    profiledialog.close();
});