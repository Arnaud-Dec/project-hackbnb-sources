import { useEffect, useState } from "react"
import { useParams, useSearchParams } from "react-router-dom"
import { apiBookingCheckoutLines, apiBookingConfirm, apiBookingDetails } from "../../api/bookings.api"
import type { Booking } from "../../types/booking"

/**
 * The page of a booking details
 */
export const BookingPage = () => {
    const { bookingId } = useParams()
    const [booking, setBooking] = useState<Booking>()
    const [checkoutLines, setCheckoutLines] = useState<any>([])
    const [searchParams, _] = useSearchParams()

    const reloadBookingDetails = async () => {
        const response = await apiBookingDetails(`${bookingId}`)
        setBooking(response.data)

        const response2 = await apiBookingCheckoutLines(`${bookingId}`, response.data.stripe_checkout_session_id)
        setCheckoutLines(response2.data)
    }

    const confirmBookingCheckout = async (confirmationSecret: string) => {
        await apiBookingConfirm(`${bookingId}`, confirmationSecret)
        await reloadBookingDetails()
    }

    useEffect(() => {
        // Mark booking as paid in API
        if (searchParams.has("checkout_confirmation_secret")) {
            confirmBookingCheckout(searchParams.get("checkout_confirmation_secret")!)
        } else {
            reloadBookingDetails()
        }
    }, [])

    return <>
        {booking && <div className="max-w-7xl m-auto px-5 py-8">
            <div className="flex gap-10">
                <div>
                    <img src={`/api/uploads/?name=${encodeURIComponent(booking.room.picture)}`} className="h-120 rounded-3xl" />
                </div>
                <div className="mt-5">
                    <h1 className="text-xl">{booking.room.title}</h1>
                    <h2 className="mt-1 text-md text-gray-300">{booking.room.city}</h2>

                    <h2 className="mt-4 text-md text-gray-300">Hôte : {booking.room.host?.name}</h2>

                    {/* D7 */}
                    <div className="mt-8 whitespace-pre-line">{booking.room.description}</div>

                    <div className="m-auto mt-10 rounded-3xl p-8 border-1 border-gray-300">
                        <h2 className="text-xl">
                            Réservation <strong className="text-gray-100">{booking.reference}</strong>
                        </h2>
                        <div className="mt-4">
                            {booking.guests_count} voyageur(s), du {new Date(booking.arrival_date).toLocaleDateString()} au {new Date(booking.departure_date).toLocaleDateString()}
                        </div>

                        {booking.is_paid && <>
                            <div className="mt-8 flex items-center gap-2">
                                <svg  xmlns="http://www.w3.org/2000/svg"  width="24"  height="24"  viewBox="0 0 24 24"  fill="none"  stroke="currentColor"  stroke-width="2"  stroke-linecap="round"  stroke-linejoin="round"><path stroke="none" d="M0 0h24v24H0z" fill="none"/><path d="M7 12l5 5l10 -10" /><path d="M2 12l5 5m5 -5l5 -5" /></svg>
                                <div>Paiement effectué, réservation confirmée</div>
                            </div>
                            <ul className="mt-2">
                                {checkoutLines.map((line: any) => (
                                    <li>&bull;&nbsp;&nbsp;{line["description"]} -- {line["amount_total"]/100} {line["currency"]}</li>
                                ))}
                            </ul>
                        </>}
                        {!booking.is_paid && <>
                            <div className="mt-8">
                                <strong>Non payé, réservation non confirmée</strong>
                            </div>
                        </>}
                    </div>
                </div>
            </div>
        </div>}
    </>
}
