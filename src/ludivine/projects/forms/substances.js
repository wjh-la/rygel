// Copyright (C) 2025  Niels Martignène <niels.martignene@protonmail.com>
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program.  If not, see <https://www.gnu.org/licenses/>.

import { html } from '../../../../vendor/lit-html/lit-html.bundle.js'
import { ASSETS } from '../../assets/assets.js'

function build(form, values) {
    form.values = values

    form.intro = html`
        <p>Les questions qui suivent portent sur des <b>comportements que vous pourriez présenter</b> (ou non) dans votre vie quotidienne. 
    `

    form.part(() => {
        form.enumButtons("tabagisme", "Fumez-vous du tabac ?", [
            ["actif", "Tabagisme actif"],
            ["sevre", "Tabagisme sevré"],
            ["non", "Non tabagique (jamais fumé)"]
        ])

        if (values.tabagisme == "actif") {
            form.enumRadio("tabagisme_qt", "Combien de paquets fumez-vous par jour ?", [
                 [1, "Moins d'un paquet"],
                 [2, "1 à 2 paquets"],
                 [3, "3 à 4 paquets"],
                 [4, "Plus de 4 paquets"]
            ], { help: "Un paquet correspond à 20 cigarettes" })
        } else if (values.tabagisme == "sevre") {
            form.number("tabagisme_sevre", "Depuis combien d'années avez-vous arrêté de fumer ?", {
                min: 0, max: 120,
                suffix: value => value > 1 ? "années" : "année"
            })
        }
    })

    form.intro = html`
        <p>Ce questionnaire interroge votre consommation d'alcool durant cette dernière année. Répondez donc en fonction de votre <b>consommation moyenne sur la dernière année</b> et non sur les dernières semaines.
        <p>Pour votre information, nous vous rappelons que tous les verres ci-dessous contiennent la même quantité d'alcool pur et sont définis comme un « verre standard » dans ce questionnaire.
        <p><i>Mais attention : une canette de 50cl d'une bière forte (8° ou 10°) contient l'équivalent de 4 verres standards et une bouteille de vin contient 8 verres standards.</i>
    `

    form.part(() => {
        form.enumButtons("audit1", "À quelle fréquence vous arrive-t-il de consommer des boissons contenant de l'alcool ?", [
            [0, "Jamais"],
            [1, "Au moins une fois par mois"],
            [2, "2 à 4 fois par mois"],
            [3, "2 à 3 fois par semaine"],
            [4, "4 fois ou plus par semaine"]
        ])
    })

    form.part(() => {
        form.output(html`
            <div style="text-align: center;">
                <img src=${ASSETS['web/misc/verres_std']} width="600" height="270"/>
            </div>
        `)

        form.enumButtons("audit2", "Combien de verres standards buvez-vous au cours d'une journée ordinaire où vous buvez de l'alcool ?", [
            [0, "1 ou 2"],
            [1, "3 ou 4"],
            [2, "4 ou 5"],
            [3, "7 à 9"],
            [4, "10 ou plus"]
        ])
    })

    form.part(() => {
        form.enumButtons("audit3", "Au cours d'une méme occasion, c4 avec moi (ok pas CRP)ombien de fois vous arrive-t-il de boire six verres standards ou plus", [
            [0, "Jamais"],
            [1, "Moins d'une fois par mois"],
            [2, "Une fois par mois"],
            [3, "Une fois par semaine"],
            [4, "Chaque jour ou presque"]
        ])

        form.enumButtons("audit4", "Dans les 12 derniers mois, combien de fois avez-vous observé que vous n'étiez plus capable de vous arrêter de boire après avoir commencé", [
            [0, "Jamais"],
            [1, "Moins d'une fois par mois"],
            [2, "Une fois par mois"],
            [3, "Une fois par semaine"],
            [4, "Chaque jour ou presque"]
        ])
    })

    form.part(() => {
        form.enumButtons("audit5", "Dans les 12 derniers mois, combien de fois le fait d'avoir bu de l'alcool, vous-a-t-il empêché de faire ce qu'on attendait normalement de vous ?", [
            [0, "Jamais"],
            [1, "Moins d'une fois par mois"],
            [2, "Une fois par mois"],
            [3, "Une fois par semaine"],
            [4, "Chaque jour ou presque"]
        ], { help: "Par exemple : aller au travail, vous rendrez à un rendez-vous"})

        form.enumButtons("audit6", "Dans les 12 derniers mois, combien de fois, après une période de forte consommation, avez-vous du boire de l'alcool dès le matin pour vous remettre en forme ?", [
            [0, "Jamais"],
            [1, "Moins d'une fois par mois"],
            [2, "Une fois par mois"],
            [3, "Une fois par semaine"],
            [4, "Chaque jour ou presque"]
        ])
    })

    form.part(() => {
        form.enumButtons("audit7", "Dans les 12 derniers mois, combien de fois avez-vou eu un sentiment de culpabilité ou de regret après avoir bu ?", [
            [0, "Jamais"],
            [1, "Moins d'une fois par mois"],
            [2, "Une fois par mois"],
            [3, "Une fois par semaine"],
            [4, "Chaque jour ou presque"]
        ])

        form.enumButtons("audit8", "Dans les 12 derniers mois, combien de fois avez vous été incapable de vous souvenir de ce qui s'était passé la nuit précédente parce que vous aviez bu ?", [
            [0, "Jamais"],
            [1, "Moins d'une fois par mois"],
            [2, "Une fois par mois"],
            [3, "Une fois par semaine"],
            [4, "Chaque jour ou presque"]
        ])
    })

    form.part(() => {
        form.enumRadio("audit9", "Vous êtes-vous blessé ou avez-vous blessé quelqu'un parce que vous aviez bu ?", [
            [0, "Non"],
            [2, "Oui mais pas dans les 12 derniers mois"],
            [4, "Oui au cours des 12 derniers mois"]
        ])

        form.enumRadio("audit10", "Est-ce qu'un parent, un ami, un médecin ou un autre professionnel de santé s'est déjà préoccupé de votre consommation d'alcool et vous a conseillé de la diminuer ?", [
            [0, "Non"],
            [2, "Oui mais pas dans les 12 derniers mois"],
            [4, "Oui au cours des 12 derniers mois"]
        ])
    })

    form.intro = html`
        <p>Indiquez désormais si vous consommez d'<b>autres substances</b>.
    `

    form.part(() => {
        form.binary("drogues1", "Êtes-vous consommateur ou consommatrice d'autres substances ?", {
            help: "Exemples : cannabis, champignons hallucinogènes, héroïne, crack, cocaïne, LSD, MDMA, ou autres substances apparentées"
        })

        if (values.drogues1) {
            form.binary("drogues2", "Était-ce déjà le cas avant l’évènement ?")
            form.number("drogues3", "Depuis combien de temps consommez-vous ces substances ?", { suffix: value => value > 1 ? "ans" : "an" })
            form.binary("drogues4", "Considérez-vous que votre consommation ait augmenté suite à l’évènement ?")
        }
    })

    form.part(() => {
        form.enumButtons("drogues5", "Vous arrive-t-il de prendre plus de comprimés ou de doses d’un médicament que ce qui est indiqué sur votre ordonnance ?", [
            [1, "Oui"],
            [0, "Non"],
            [99, "Non applicable"]
        ], { help: "Exemples : psychotropes, antidouleurs, anxiolytiques, ou autres substances apparentées" })
    })
}

export default build
