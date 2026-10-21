document.addEventListener("DOMContentLoaded", () => {

    const heroContent = document.querySelector(".hero-content");
    const heroGraphic = document.querySelector(".hero-graphic");

    heroContent.style.opacity = "0";
    heroContent.style.transform = "translateY(25px)";

    heroGraphic.style.opacity = "0";
    heroGraphic.style.transform = "scale(.96)";

    setTimeout(() => {
        heroContent.style.transition = "all .8s ease";
        heroContent.style.opacity = "1";
        heroContent.style.transform = "translateY(0)";
    }, 100);

    setTimeout(() => {
        heroGraphic.style.transition = "all 1s ease";
        heroGraphic.style.opacity = "1";
        heroGraphic.style.transform = "scale(1)";
    }, 300);


    /* Floating cards */

    const cards = document.querySelectorAll(".data-card");

    cards.forEach((card, index) => {

        card.animate(
            [
                { transform: "translateY(0)" },
                { transform: "translateY(-8px)" },
                { transform: "translateY(0)" }
            ],
            {
                duration: 3000 + index * 500,
                iterations: Infinity,
                easing: "ease-in-out"
            }
        );

    });

});
/* =================================
   ACCORDION
================================= */

document.addEventListener("DOMContentLoaded", function () {

    const accordionButtons =
        document.querySelectorAll(".accordion-btn");


    accordionButtons.forEach(function (button) {

        button.addEventListener("click", function () {

            const currentItem =
                this.closest(".accordion-item");


            const allItems =
                document.querySelectorAll(".accordion-item");


            allItems.forEach(function (item) {

                if (item !== currentItem) {

                    item.classList.remove("open");

                }

            });


            currentItem.classList.toggle("open");

        });

    });

});