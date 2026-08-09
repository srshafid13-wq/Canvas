document.addEventListener(
    "DOMContentLoaded",
    function () {

        const title =
            localStorage.getItem(
                "canvasStreamTitle"
            );

        const category =
            localStorage.getItem(
                "canvasStreamCategory"
            );


        if (title) {

            console.log(
                "Current Canvas stream:",
                title
            );

            console.log(
                "Category:",
                category
            );

        }

    }
);
