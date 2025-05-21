setTimeout(() => {
    document.querySelectorAll('.toast-success').forEach((toast) => {
        toast.style.display = "none";
    });
}, 3000);