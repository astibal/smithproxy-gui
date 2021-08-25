import Head from 'next/head'
import styles from './layout.module.css'

import Link from 'next/link'

export const siteTitle = 'Smithproxy GUI'

export default function Layout({ children, home }) {
    return (
        <div className={styles.container}>
            <Head>
                <meta name="og:title" content={siteTitle} />
                <meta name="twitter:card" content="summary_large_image" />
                <title>{siteTitle}</title>
            </Head>
            <header className={styles.header}>
            </header>
            <main>{children}</main>
            {!home && (
                <div className={styles.backToHome}>
                    <Link href="/">
                        <a>← Back to home</a>
                    </Link>
                </div>
            )}
        </div>
    )
}