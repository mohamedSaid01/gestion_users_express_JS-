import transport from '../middlewares/sendMail.js'


// Fonction pour envoyer un email d'alerte en cas d'activité suspecte
export const sendSuspiciousActivityEmail = async (email, fullName, failedLoginAttempts, timeSinceLastFailed) => {
  try {

    const mailOptions = {
      from: process.env.NODE_CODE_SENDING_EMAIL_ADDRESS,
      to: email,
      subject: 'Alerte : Activité suspecte détectée sur votre compte',
      text: `Bonjour ${fullName},\n\nNous avons détecté une activité suspecte sur votre compte : ${failedLoginAttempts} tentatives de connexion échouées, Votre compte a été temporairement verrouillé pour 15 minutes. Si ce n'était pas vous, veuillez sécuriser votre compte immédiatement en changeant votre mot de passe.\n\nCordialement,\nL'équipe de gestion des utilisateurs`
    };

    await transport.sendMail(mailOptions);
    console.log(`Email d'alerte envoyé à ${email}`);
  } catch (error) {
    console.error(`Erreur lors de l'envoi de l'email d'alerte à ${email}:`, error);
    throw new Error('Erreur lors de l’envoi de l’email d’alerte');
  }
};